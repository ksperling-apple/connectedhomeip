/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// Commissioning a device onto a Wi-Fi network that uses Per-Device Credentials (PDC), i.e. Matter
// Core specification chapter 15. The work is split between the AutoCommissioner, which decides the
// stage sequence and owns the buffers the identities are copied into, and the DeviceCommissioner,
// which drives the NetworkIdentityRegistrar, verifies the commissionee's proof of possession, and
// owns the rollback; there is a fixture for each.

#include <pw_unit_test/framework.h>

#include <app/DeviceProxy.h>
#include <controller/AutoCommissioner.h>
#include <controller/CHIPDeviceController.h>
#include <controller/CommissioneeDeviceProxy.h>
#include <controller/CommissioningDelegate.h>
#include <controller/NetworkIdentityRegistrar.h>
#include <controller/tests/AutoCommissionerTestAccess.h>
#include <controller/tests/DeviceCommissionerTestAccess.h>
#include <credentials/CHIPCert.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>

#include <cstring>

using namespace chip;
using namespace chip::app::Clusters;
using namespace chip::Controller;
using namespace chip::Testing;

namespace {

// Records what the commissioner asked of it. GetNetworkIdentity() is never reached by either
// fixture, and RegisterClient() only by tests that opt in with AcceptRegistrations(), so those fail
// here to catch unexpected calls.
class MockNetworkIdentityRegistrar : public NetworkIdentityRegistrar
{
public:
    CHIP_ERROR GetNetworkIdentity(Callback::Callback<OnNetworkIdentityAvailableFunct>::Owned) override
    {
        ADD_FAILURE() << "unexpected GetNetworkIdentity()";
        return CHIP_ERROR_INCORRECT_STATE;
    }

    void AcceptRegistrations() { mAcceptRegistrations = true; }

    CHIP_ERROR RegisterClient(ByteSpan clientIdentity, Callback::Callback<OnClientRegisteredFunct>::Owned onCompletion) override
    {
        if (!mAcceptRegistrations)
        {
            ADD_FAILURE() << "unexpected RegisterClient()";
            return CHIP_ERROR_INCORRECT_STATE;
        }
        mRegisterCalls++;
        VerifyOrReturnError(clientIdentity.size() <= sizeof(mRegisteredIdentity), CHIP_ERROR_BUFFER_TOO_SMALL);
        memcpy(mRegisteredIdentity, clientIdentity.data(), clientIdentity.size());
        mRegisteredIdentityLen = clientIdentity.size();

        // Completing synchronously is explicitly allowed, and there is no bookkeeping to it: the
        // callback was never registered with us, so the caller has no opportunity to cancel it.
        onCompletion.Invoke(CHIP_NO_ERROR);
        return CHIP_NO_ERROR;
    }

    /// Hold UnregisterClient() calls instead of completing them re-entrantly, so a test can drive the
    /// points where the commissioner waits for a revocation.
    void DeferRevocations() { mDeferRevocations = true; }

    bool HasPendingRevocation() const { return mPendingUnregister != nullptr; }

    /// Completes a held revocation, as a registrar does once it has heard back from the network.
    void CompleteRevocation(CHIP_ERROR status = CHIP_NO_ERROR)
    {
        Callback::Cancelable * cancelable = mPendingUnregister;
        ASSERT_NE(cancelable, nullptr);
        mPendingUnregister = nullptr;

        // Surrender our registration before completing, so that the callback is a one-shot. Note this
        // must not go through Cancel(): that runs OnRevocationCancelled(), which is how we recognise
        // the commissioner giving up on a revocation, and a completion is the opposite of that. Clearing
        // mCancel is enough -- the fields we borrowed are indeterminate again once we are unregistered.
        cancelable->mCancel = nullptr;

        auto * onCompletion = Callback::Callback<OnClientUnregisteredFunct>::FromCancelable(cancelable);
        onCompletion->Invoke(status);
    }

    CHIP_ERROR UnregisterClient(ByteSpan clientIdentifier,
                                Callback::Callback<OnClientUnregisteredFunct>::Owned onCompletion) override
    {
        mUnregisterCalls++;
        VerifyOrReturnError(clientIdentifier.size() <= sizeof(mUnregisteredIdentifier), CHIP_ERROR_BUFFER_TOO_SMALL);
        memcpy(mUnregisteredIdentifier, clientIdentifier.data(), clientIdentifier.size());
        mUnregisteredIdentifierLen = clientIdentifier.size();

        if (!mDeferRevocations)
        {
            onCompletion.Invoke(CHIP_NO_ERROR);
            return CHIP_NO_ERROR;
        }

        // Enforce the contract rather than quietly taking the callback over, as a real registrar does:
        // a caller only ever has one registration to give up, so this means it has lost track of one.
        // (A caller reusing the same callback object cancels the previous revocation when it hands the
        // callback over, and so is never caught by this.)
        VerifyOrReturnError(mPendingUnregister == nullptr, CHIP_ERROR_INCORRECT_STATE);

        // Take ownership of the Cancelable and install a cancel function, so that IsRegistered()
        // holds while the request is in flight and we notice if the commissioner gives up on it.
        Callback::Cancelable * cancelable = onCompletion.Take();
        cancelable->mContextA             = this;
        cancelable->mCancel               = OnRevocationCancelled;
        mPendingUnregister                = cancelable;
        return CHIP_NO_ERROR;
    }

    ByteSpan RegisteredIdentity() const { return ByteSpan(mRegisteredIdentity, mRegisteredIdentityLen); }
    ByteSpan UnregisteredIdentifier() const { return ByteSpan(mUnregisteredIdentifier, mUnregisteredIdentifierLen); }

    unsigned mRegisterCalls        = 0;
    unsigned mUnregisterCalls      = 0;
    unsigned mCancelledRevocations = 0;

private:
    static void OnRevocationCancelled(Callback::Cancelable * cancelable)
    {
        auto * self = static_cast<MockNetworkIdentityRegistrar *>(cancelable->mContextA);
        self->mCancelledRevocations++;
        self->mPendingUnregister = nullptr;
    }

    bool mAcceptRegistrations                 = false;
    bool mDeferRevocations                    = false;
    Callback::Cancelable * mPendingUnregister = nullptr;
    uint8_t mRegisteredIdentity[Credentials::kMaxCHIPCompactNetworkIdentityLength];
    size_t mRegisteredIdentityLen = 0;
    uint8_t mUnregisteredIdentifier[Credentials::kKeyIdentifierLength];
    size_t mUnregisteredIdentifierLen = 0;
};

constexpr char kSsidChars[]       = "test-network";
constexpr char kPassphraseChars[] = "passphrase";
const ByteSpan kSsid(reinterpret_cast<const uint8_t *>(kSsidChars), sizeof(kSsidChars) - 1);
const ByteSpan kPassphrase(reinterpret_cast<const uint8_t *>(kPassphraseChars), sizeof(kPassphraseChars) - 1);

// Arbitrary fixed nonce, for tests that are not concerned with how the real one is generated.
constexpr uint8_t kPossessionNonceBytes[CommissioningParameters::kPossessionNonceLen] = { 0xa5 };
const ByteSpan kPossessionNonce(kPossessionNonceBytes);

// A Network (Client) Identity and the key needed to sign a possession nonce with it.
class TestNetworkIdentity
{
public:
    TestNetworkIdentity()
    {
        VerifyOrDie(mKeypair.Initialize(Crypto::ECPKeyTarget::ECDSA) == CHIP_NO_ERROR);
        MutableByteSpan identity(mIdentityBuffer);
        VerifyOrDie(Credentials::NewChipNetworkIdentity(mKeypair, identity) == CHIP_NO_ERROR);
        mIdentityLen = identity.size();
    }

    ByteSpan Identity() const { return ByteSpan(mIdentityBuffer, mIdentityLen); }

    // Produces a signature over (identity || nonce), i.e. the proof of possession the commissionee
    // is required to return alongside its Network Client Identity.
    CHIP_ERROR SignPossession(ByteSpan nonce, Crypto::P256ECDSASignature & signature) const
    {
        uint8_t tbs[sizeof(mIdentityBuffer) + CommissioningParameters::kPossessionNonceLen];
        VerifyOrReturnError(mIdentityLen + nonce.size() <= sizeof(tbs), CHIP_ERROR_BUFFER_TOO_SMALL);
        memcpy(tbs, mIdentityBuffer, mIdentityLen);
        memcpy(tbs + mIdentityLen, nonce.data(), nonce.size());
        return mKeypair.ECDSA_sign_msg(tbs, mIdentityLen + nonce.size(), signature);
    }

private:
    Crypto::P256Keypair mKeypair;
    uint8_t mIdentityBuffer[Credentials::kMaxCHIPCompactNetworkIdentityLength];
    size_t mIdentityLen = 0;
};

// ---------------------------------------------------------------------------
// AutoCommissioner
// ---------------------------------------------------------------------------

// CommissioningStepFinished() processes the report, works out the next stage, and then performs it.
// This fixture has no device proxy to perform anything against, so PerformStep() bails out with
// this error. Reaching that point is what tells us the report was processed and the flow was
// routed, which is all these tests are about; a report the AutoCommissioner rejects fails earlier
// and with its own distinct error, which the tests covering that assert directly.
//
// Driving the steps for real is not an option here: DeviceCommissioner::PerformCommissioningStep()
// is not virtual, so it cannot be stubbed out, and performing it in earnest needs a live PASE
// session. End-to-end coverage belongs in the TestCommissioner harness in OpCredsBinding.cpp, which
// needs a NetworkIdentityRegistrar implementation and a PDC-capable commissionee to exist first.
constexpr CHIP_ERROR kStoppedAtPerformStep = CHIP_ERROR_INCORRECT_STATE;

// The stage sequence PDC produces, and the buffers the identities are copied into on the way through.
class AutoCommissionerPDCTest : public ::testing::Test
{
protected:
    // Sets up a commissionee that only supports Wi-Fi, and applies the given parameters.
    void Configure(const CommissioningParameters & params, bool supportsPDC)
    {
        ASSERT_EQ(mCommissioner.SetCommissioningParameters(params), CHIP_NO_ERROR);
        mAccess.SetCommissioner(&mDeviceCommissioner);

        ReadCommissioningInfo & info                   = mAccess.GetDeviceCommissioningInfo();
        info.network.wifi.endpoint                     = kRootEndpointId;
        info.network.wifi.supportsPerDeviceCredentials = supportsPDC;
        info.network.thread.endpoint                   = kInvalidEndpointId;
    }

    // Parameters carrying an SSID and a registrar, with no passphrase to fall back on.
    CommissioningParameters PDCOnlyParams()
    {
        CommissioningParameters params;
        params.SetWiFiCredentials(WiFiCredentials(kSsid, &mRegistrar));
        return params;
    }

    // Parameters carrying an SSID, a registrar, and a passphrase (possibly empty) as a fallback.
    CommissioningParameters PDCWithFallbackParams(ByteSpan passphrase)
    {
        CommissioningParameters params;
        params.SetWiFiCredentials(WiFiCredentials(kSsid, &mRegistrar, passphrase));
        return params;
    }

    // Drives the stage the AutoCommissioner would be in after a successful kGetNetworkIdentity,
    // which is what makes the network's Network Identity available.
    void CompleteGetNetworkIdentity()
    {
        CommissioningDelegate::CommissioningReport report;
        report.stageCompleted = kGetNetworkIdentity;
        report.Set<WiFiPDCNetworkIdentityInfo>(mNetworkIdentity.Identity());
        EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_NO_ERROR, report), kStoppedAtPerformStep);
    }

    // Feeds back the client identity and possession signature a PDC commissionee would return.
    CHIP_ERROR CompleteWiFiNetworkSetup()
    {
        Crypto::P256ECDSASignature signature;
        VerifyOrDie(mClientIdentity.SignPossession(PossessionNonce(), signature) == CHIP_NO_ERROR);

        CommissioningDelegate::CommissioningReport report;
        report.stageCompleted = kWiFiNetworkSetup;
        report.Set<WiFiPDCClientIdentityInfo>(mClientIdentity.Identity(), signature.Span());
        return mCommissioner.CommissioningStepFinished(CHIP_NO_ERROR, report);
    }

    ByteSpan PossessionNonce() { return mAccess.AccessParams().GetPDCPossessionNonce().Value(); }

    void SetCompletionError(CHIP_ERROR err)
    {
        CompletionStatus status;
        status.err = err;
        mAccess.AccessParams().SetCompletionStatus(status);
    }

    AutoCommissioner mCommissioner{};
    AutoCommissionerTestAccess mAccess{ &mCommissioner };
    DeviceCommissioner mDeviceCommissioner{};
    MockNetworkIdentityRegistrar mRegistrar;
    TestNetworkIdentity mNetworkIdentity;
    TestNetworkIdentity mClientIdentity;
};

// A registrar plus a PDC-capable commissionee takes the PDC path; once the Network Identity has
// been obtained the flow rejoins kWiFiNetworkSetup, with the client identity installed before the
// network is enabled.
TEST_F(AutoCommissionerPDCTest, StageGraphWithRegistrarAndPDCSupport)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    CHIP_ERROR err = CHIP_NO_ERROR;

    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kGetNetworkIdentity);
    EXPECT_EQ(err, CHIP_NO_ERROR);

    CompleteGetNetworkIdentity();
    ASSERT_TRUE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());

    // Now that we have the identity, the fetch is not repeated.
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kGetNetworkIdentity, err), kWiFiNetworkSetup);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kWiFiNetworkSetup, err), kInstallClientIdentity);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kInstallClientIdentity, err), kFailsafeBeforeWiFiEnable);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// Supplying the registrar late, in response to kNeedsNetworkCreds, must converge on the same graph.
TEST_F(AutoCommissionerPDCTest, StageGraphConvergesForLateSuppliedRegistrar)
{
    // First pass: no credentials at all, so the commissioner asks for them.
    Configure(CommissioningParameters(), /* supportsPDC = */ true);
    CHIP_ERROR err = CHIP_NO_ERROR;
    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kICDRegistration, err), kRequestWiFiCredentials);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kRequestWiFiCredentials, err), kNeedsNetworkCreds);

    // The application answers with an SSID and a registrar, exactly as it would up front.
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kNeedsNetworkCreds, err), kGetNetworkIdentity);

    CompleteGetNetworkIdentity();
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kGetNetworkIdentity, err), kWiFiNetworkSetup);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kWiFiNetworkSetup, err), kInstallClientIdentity);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// A registrar is not usable against a commissionee without the PDC feature; a passphrase supplied
// alongside it is the fallback.
TEST_F(AutoCommissionerPDCTest, PassphraseIsUsedWhenCommissioneeLacksPDC)
{
    Configure(PDCWithFallbackParams(kPassphrase), /* supportsPDC = */ false);
    CHIP_ERROR err = CHIP_NO_ERROR;

    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kWiFiNetworkSetup);
    // No Network Identity, so no client identity to install either.
    EXPECT_FALSE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kWiFiNetworkSetup, err), kFailsafeBeforeWiFiEnable);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// An empty passphrase is a valid configuration -- an open network -- and must not be mistaken for
// "no passphrase supplied", which is what a PDC-only registrar means.
TEST_F(AutoCommissionerPDCTest, OpenNetworkIsUsedAsFallbackWhenCommissioneeLacksPDC)
{
    Configure(PDCWithFallbackParams(ByteSpan()), /* supportsPDC = */ false);
    CHIP_ERROR err = CHIP_NO_ERROR;

    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kWiFiNetworkSetup);
    EXPECT_EQ(err, CHIP_NO_ERROR);
    ASSERT_TRUE(mAccess.AccessParams().GetWiFiCredentials().HasValue());
    EXPECT_TRUE(mAccess.AccessParams().GetWiFiCredentials().Value().hasCredentials);
    EXPECT_TRUE(mAccess.AccessParams().GetWiFiCredentials().Value().credentials.empty());
}

// An open network without any registrar involved must behave exactly as it did before PDC existed.
TEST_F(AutoCommissionerPDCTest, OpenNetworkWithoutRegistrarIsConfigured)
{
    CommissioningParameters params;
    params.SetWiFiCredentials(WiFiCredentials(kSsid, ByteSpan()));
    Configure(params, /* supportsPDC = */ true);
    CHIP_ERROR err = CHIP_NO_ERROR;

    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kWiFiNetworkSetup);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kWiFiNetworkSetup, err), kFailsafeBeforeWiFiEnable);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// "PDC and nothing else" against a commissionee that cannot do PDC is unsatisfiable. Rather than
// deciding that during stage selection, we run kWiFiNetworkSetup anyway and let the commissioner
// reject it, which puts us on the ordinary step-failure path. With no other network to try, the
// attempt ends and the error is reported rather than swallowed.
TEST_F(AutoCommissionerPDCTest, PDCOnlyFailsWhenCommissioneeLacksPDC)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ false);
    CHIP_ERROR err = CHIP_NO_ERROR;

    // No Network Identity was obtained, so kWiFiNetworkSetup has nothing to configure the
    // commissionee with; see DeviceCommissionerPDCTest.RejectsPDCOnlyCredentialsWithoutIdentity.
    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kWiFiNetworkSetup);
    EXPECT_EQ(err, CHIP_NO_ERROR);
    EXPECT_FALSE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());

    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkSetup;
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_ERROR_INVALID_ARGUMENT, report), kStoppedAtPerformStep);
    EXPECT_FALSE(mAccess.TryingSecondaryNetwork());
    EXPECT_EQ(mAccess.AccessParams().GetCompletionStatus().err, CHIP_ERROR_INVALID_ARGUMENT);
}

// ...but if the application also supplied a Thread dataset, then "Wi-Fi via PDC or Thread" is what
// it asked for, so the rejected Wi-Fi stage fails over to the secondary network.
TEST_F(AutoCommissionerPDCTest, PDCOnlyFallsBackToSecondaryNetworkWhenCommissioneeLacksPDC)
{
    CommissioningParameters params = PDCOnlyParams();
    params.SetThreadOperationalDataset(ByteSpan());
    params.SetSupportsConcurrentConnection(true);
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(params), CHIP_NO_ERROR);
    mAccess.SetCommissioner(&mDeviceCommissioner);

    ReadCommissioningInfo & info                   = mAccess.GetDeviceCommissioningInfo();
    info.network.wifi.endpoint                     = kRootEndpointId;
    info.network.wifi.supportsPerDeviceCredentials = false;
    info.network.thread.endpoint                   = 1;

    CHIP_ERROR err = CHIP_NO_ERROR;
    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kWiFiNetworkSetup);
    ASSERT_TRUE(mAccess.TryingPrimaryNetwork());

    // The commissioner rejects the stage, and that is treated as any other network failure.
    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkSetup;
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_ERROR_INVALID_ARGUMENT, report), kStoppedAtPerformStep);
    EXPECT_TRUE(mAccess.TryingSecondaryNetwork());

    // We never wrote a configuration, so there is nothing to remove on the way to Thread.
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kPrimaryOperationalNetworkFailed, err), kThreadNetworkSetup);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// A plain passphrase must produce exactly the graph it produced before PDC existed, whether or not
// the commissionee happens to support PDC.
TEST_F(AutoCommissionerPDCTest, PassphraseOnlyIsUnaffectedByPDCSupport)
{
    for (bool supportsPDC : { false, true })
    {
        CommissioningParameters params;
        params.SetWiFiCredentials(WiFiCredentials(kSsid, kPassphrase));
        Configure(params, supportsPDC);
        CHIP_ERROR err = CHIP_NO_ERROR;

        EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kWiFiNetworkSetup);
        EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kWiFiNetworkSetup, err), kFailsafeBeforeWiFiEnable);
        EXPECT_EQ(err, CHIP_NO_ERROR);
    }
}

// A fresh possession nonce is generated for each PDC exchange, and an application-supplied one is
// honoured, as for the attestation and CSR nonces.
TEST_F(AutoCommissionerPDCTest, PossessionNonceIsGeneratedUnlessSupplied)
{
    // Nothing is generated until we know we are actually going to configure a commissionee for PDC.
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    EXPECT_FALSE(mAccess.AccessParams().GetPDCPossessionNonce().HasValue());

    CompleteGetNetworkIdentity();
    ASSERT_TRUE(mAccess.AccessParams().GetPDCPossessionNonce().HasValue());
    ASSERT_EQ(PossessionNonce().size(), CommissioningParameters::kPossessionNonceLen);

    // Resetting the PDC state discards the nonce, so the next exchange uses a different challenge.
    uint8_t previousNonce[CommissioningParameters::kPossessionNonceLen];
    memcpy(previousNonce, PossessionNonce().data(), sizeof(previousNonce));
    mAccess.ClearPDCParameters();
    CompleteGetNetworkIdentity();
    EXPECT_FALSE(PossessionNonce().data_equal(ByteSpan(previousNonce)));

    // An application-supplied nonce is copied up front and used as-is.
    uint8_t suppliedNonce[CommissioningParameters::kPossessionNonceLen];
    memset(suppliedNonce, 0xA5, sizeof(suppliedNonce));
    CommissioningParameters params = PDCOnlyParams();
    params.SetPDCPossessionNonce(ByteSpan(suppliedNonce));
    Configure(params, /* supportsPDC = */ true);
    EXPECT_TRUE(PossessionNonce().data_equal(ByteSpan(suppliedNonce)));
    CompleteGetNetworkIdentity();
    EXPECT_TRUE(PossessionNonce().data_equal(ByteSpan(suppliedNonce)));

    // A wrongly sized nonce is rejected rather than silently truncated / extended
    uint8_t shortNonce[CommissioningParameters::kPossessionNonceLen - 1] = {};
    CommissioningParameters badParams                                    = PDCOnlyParams();
    badParams.SetPDCPossessionNonce(ByteSpan(shortNonce));
    EXPECT_EQ(mCommissioner.SetCommissioningParameters(badParams), CHIP_ERROR_INVALID_ARGUMENT);
}

// The AutoCommissioner takes its own copy of the client identity and signature, because the report's
// spans point into the response message buffer. Verification is the DeviceCommissioner's job.
TEST_F(AutoCommissionerPDCTest, CapturesClientIdentityAndPossessionSignature)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    CompleteGetNetworkIdentity();

    EXPECT_EQ(CompleteWiFiNetworkSetup(), kStoppedAtPerformStep);
    ASSERT_TRUE(mAccess.AccessParams().GetPDCClientIdentity().HasValue());
    EXPECT_TRUE(mAccess.AccessParams().GetPDCClientIdentity().Value().data_equal(mClientIdentity.Identity()));
    ASSERT_TRUE(mAccess.AccessParams().GetPDCPossessionSignature().HasValue());
    EXPECT_EQ(mAccess.AccessParams().GetPDCPossessionSignature().Value().size(), CommissioningParameters::kPossessionSignatureLen);
}

// ...and this is the one test that puts both halves together, because the handover is the only place
// the possession nonce the AutoCommissioner generated meets the verification the DeviceCommissioner
// does with it: neither fixture on its own can tell that those two agree.
//
// Only the stages that send a command to the commissionee are stood in for, by reporting them
// complete as the commissionee would. Everything in between really runs, in the real
// DeviceCommissioner, off the AutoCommissioner's own stage decisions -- including the rollback,
// which is what a DeviceCommissioner stage entails rather than something a test can ask for. Note it
// is kCleanup that entails it here, not kRemoveWiFiNetworkConfig: that stage sends RemoveNetwork, so
// performing it needs a session this fixture has no way to produce (see kStoppedAtPerformStep), and
// DeviceCommissionerRevocationTest drives its response handler directly instead.
TEST_F(AutoCommissionerPDCTest, InstalledIdentityIsRegisteredAndRolledBackOnFailure)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    mRegistrar.AcceptRegistrations();
    CompleteGetNetworkIdentity();

    // Give the AutoCommissioner a commissionee to hang the stages off, so that the steps it picks
    // reach the DeviceCommissioner rather than being lost in PerformStep().
    CommissioneeDeviceProxy commissionee;
    mAccess.SetCommissioneeDeviceProxy(&commissionee);

    // Reporting kWiFiNetworkSetup complete drives all of the following in one synchronous chain:
    //   kInstallClientIdentity     registers the identity with the network, having checked the
    //                              commissionee's proof of possession against our own nonce
    //   kFailsafeBeforeWiFiEnable  fails, because this commissioner has no commissionee device of its
    //                              own to extend the fail-safe on. Any mid-flow failure would do; this
    //                              is the one the fixture can produce without sending a command.
    //   kCleanup                   rolls the registration back, the attempt having failed
    ASSERT_EQ(CompleteWiFiNetworkSetup(), CHIP_NO_ERROR);
    const CompletionStatus & status = mAccess.AccessParams().GetCompletionStatus();
    ASSERT_EQ(status.err, CHIP_ERROR_INCORRECT_STATE) << "the attempt failed somewhere unexpected";
    ASSERT_TRUE(status.failedStage.HasValue());
    ASSERT_EQ(status.failedStage.Value(), kFailsafeBeforeWiFiEnable);

    // The identity the network was given is the one the commissionee returned, so the possession
    // signature was accepted over the nonce the AutoCommissioner generated and stored.
    EXPECT_EQ(mRegistrar.mRegisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.RegisteredIdentity().data_equal(mClientIdentity.Identity()));

    // ...and it was revoked again by its key identifier, which only the DeviceCommissioner computed.
    Credentials::CertificateKeyIdStorage clientIdentifier{};
    ASSERT_EQ(Credentials::ExtractIdentifierFromChipNetworkIdentity(mClientIdentity.Identity(),
                                                                    Credentials::MutableCertificateKeyId(clientIdentifier)),
              CHIP_NO_ERROR);
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.UnregisteredIdentifier().data_equal(ByteSpan(clientIdentifier)));
    EXPECT_EQ(DeviceCommissionerTestAccess(&mDeviceCommissioner).GetNetworkClientRegistrar(), nullptr);
}

// A commissionee that reports success without returning a client identity is not conformant; make
// sure we fail cleanly rather than reading an unset report.
TEST_F(AutoCommissionerPDCTest, RejectsMissingClientIdentity)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    CompleteGetNetworkIdentity();

    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkSetup;
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_NO_ERROR, report), CHIP_ERROR_MISSING_TLV_ELEMENT);
    EXPECT_FALSE(mAccess.AccessParams().GetPDCClientIdentity().HasValue());
}

// A signature of the wrong length cannot be verified later, so reject it on the way in rather than
// storing a short value in a fixed-size buffer.
TEST_F(AutoCommissionerPDCTest, RejectsWrongLengthPossessionSignature)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    CompleteGetNetworkIdentity();

    uint8_t shortSignature[CommissioningParameters::kPossessionSignatureLen - 1] = {};
    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkSetup;
    report.Set<WiFiPDCClientIdentityInfo>(mClientIdentity.Identity(), ByteSpan(shortSignature));
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_NO_ERROR, report), CHIP_ERROR_INVALID_SIGNATURE);
    EXPECT_FALSE(mAccess.AccessParams().GetPDCClientIdentity().HasValue());
}

// Why the PDC parameters are left alone when the Wi-Fi configuration is removed: that stage is only
// reachable from kPrimaryOperationalNetworkFailed with Wi-Fi on the root endpoint, so by the time it
// completes we are committed to the secondary network and the next selection is Thread, which reads
// no PDC parameters. They are stale but inert, and CleanupCommissioning() clears them at the end of
// the attempt. (Revoking the client identity registration is the DeviceCommissioner's job, off the
// back of the RemoveNetwork response.)
TEST_F(AutoCommissionerPDCTest, RemovingWiFiConfigProceedsToThreadNetworkSetup)
{
    CommissioningParameters params = PDCOnlyParams();
    params.SetThreadOperationalDataset(ByteSpan());
    params.SetSupportsConcurrentConnection(true);
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(params), CHIP_NO_ERROR);
    mAccess.SetCommissioner(&mDeviceCommissioner);

    ReadCommissioningInfo & info                   = mAccess.GetDeviceCommissioningInfo();
    info.network.wifi.endpoint                     = kRootEndpointId;
    info.network.wifi.supportsPerDeviceCredentials = true;
    info.network.thread.endpoint                   = 1;

    // Configure the commissionee for PDC on the primary (Wi-Fi) network.
    CHIP_ERROR err = CHIP_NO_ERROR;
    EXPECT_EQ(mAccess.GetNextCommissioningStageNetworkSetup(kNeedsNetworkCreds, err), kGetNetworkIdentity);
    ASSERT_TRUE(mAccess.TryingPrimaryNetwork());
    CompleteGetNetworkIdentity();
    EXPECT_EQ(CompleteWiFiNetworkSetup(), kStoppedAtPerformStep);

    // ConnectNetwork failed outright, so the primary network is given up on. Note the absence of a
    // NetworkCommissioningStatusInfo report: this is the failover path, not the retry path.
    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkEnable;
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_ERROR_INTERNAL, report), kStoppedAtPerformStep);
    ASSERT_TRUE(mAccess.TryingSecondaryNetwork());

    // That failover is the only way to reach kRemoveWiFiNetworkConfig, and from there the flow can
    // only go to Thread; the Wi-Fi branch of the network selection is never entered again.
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kPrimaryOperationalNetworkFailed, err), kRemoveWiFiNetworkConfig);
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kRemoveWiFiNetworkConfig, err), kThreadNetworkSetup);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// A failed network configuration that the application is allowed to retry walks the flow back to
// kScanNetworks, and this is the one case where the PDC parameters have to go: the retry re-enters
// the Wi-Fi branch, and reusing the Network Identity (never mind the possession nonce) would mean
// challenging the commissionee with a nonce it has already answered.
TEST_F(AutoCommissionerPDCTest, RetryingAfterNetworkEnableFailureClearsPDCParameters)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);

    // The retry is gated on IsScanNeeded(), which cannot be arranged through the application-level
    // parameters: SetWiFiCredentials() clears the scan flag, and AutoCommissioner::
    // SetCommissioningParameters() re-applies the credentials, so it has to be set on the
    // AutoCommissioner's own copy afterwards. Scanning is the wrong condition in the first place --
    // see the TODO above the IsScanNeeded() check in CommissioningStepFinished() -- and this
    // workaround goes away with the follow-up change to the restart flow.
    mAccess.AccessParams().SetAttemptWiFiNetworkScan(true);
    ASSERT_TRUE(mAccess.IsScanNeeded());

    CompleteGetNetworkIdentity();
    EXPECT_EQ(CompleteWiFiNetworkSetup(), kStoppedAtPerformStep);
    ASSERT_TRUE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());

    // Give the AutoCommissioner a commissionee to talk to, so that the stage it restarts at is
    // actually driven rather than lost in PerformStep().
    CommissioneeDeviceProxy commissionee;
    mAccess.SetCommissioneeDeviceProxy(&commissionee);

    // ConnectNetwork failed: the commissionee could not find the network we configured.
    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkEnable;
    report.Set<NetworkCommissioningStatusInfo>(
        app::Clusters::NetworkCommissioning::NetworkCommissioningStatusEnum::kNetworkNotFound, CharSpan());
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_ERROR_INTERNAL, report), CHIP_NO_ERROR);

    // Walked back to kScanNetworks, whose successor asks the application for credentials again.
    EXPECT_EQ(mDeviceCommissioner.GetCommissioningStage(), kNeedsNetworkCreds);
    EXPECT_FALSE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());
    EXPECT_FALSE(mAccess.AccessParams().GetPDCPossessionNonce().HasValue());
    EXPECT_FALSE(mAccess.AccessParams().GetPDCClientIdentity().HasValue());
    EXPECT_FALSE(mAccess.AccessParams().GetPDCPossessionSignature().HasValue());
}

// What that walk-back does *not* do is give up the Network Client Identity registered for the
// configuration it is retrying: the registration is only rolled back on RemoveNetwork or at the end
// of the attempt, neither of which the walk-back goes through. So the retry runs into the
// single-outstanding-registration check in kInstallClientIdentity and fails the attempt, which is
// what finally revokes the stale registration -- see the second TODO above the IsScanNeeded() check
// in CommissioningStepFinished(). This test pins that behaviour rather than endorsing it; a retry
// that removed the old configuration first would not get here at all.
TEST_F(AutoCommissionerPDCTest, RetryingWithAnOutstandingRegistrationFailsTheAttempt)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    mAccess.AccessParams().SetAttemptWiFiNetworkScan(true); // see the test above
    ASSERT_TRUE(mAccess.IsScanNeeded());

    CompleteGetNetworkIdentity();
    EXPECT_EQ(CompleteWiFiNetworkSetup(), kStoppedAtPerformStep);

    // The install this fixture cannot perform (kWiFiNetworkSetup was never sent, so neither was the
    // step after it) would have left the commissioner holding exactly this.
    Credentials::CertificateKeyIdStorage clientIdentifier{};
    ASSERT_EQ(Credentials::ExtractIdentifierFromChipNetworkIdentity(mClientIdentity.Identity(),
                                                                    Credentials::MutableCertificateKeyId(clientIdentifier)),
              CHIP_NO_ERROR);
    DeviceCommissionerTestAccess deviceCommissionerAccess{ &mDeviceCommissioner };
    deviceCommissionerAccess.SetNetworkClientRegistration(&mRegistrar, ByteSpan(clientIdentifier));

    CommissioneeDeviceProxy commissionee;
    mAccess.SetCommissioneeDeviceProxy(&commissionee);

    // ConnectNetwork failed: the commissionee could not find the network we configured.
    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kWiFiNetworkEnable;
    report.Set<NetworkCommissioningStatusInfo>(
        app::Clusters::NetworkCommissioning::NetworkCommissioningStatusEnum::kNetworkNotFound, CharSpan());
    ASSERT_EQ(mCommissioner.CommissioningStepFinished(CHIP_ERROR_INTERNAL, report), CHIP_NO_ERROR);
    ASSERT_EQ(mDeviceCommissioner.GetCommissioningStage(), kNeedsNetworkCreds);

    // Walking back is not an end to the attempt, so we are still on the hook for the registration.
    EXPECT_EQ(deviceCommissionerAccess.GetNetworkClientRegistrar(), &mRegistrar);
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 0u);

    // The application answers with credentials again and the flow runs up to the second install,
    // which the commissioner refuses. The registrar is left to fail an unexpected RegisterClient().
    mAccess.SetCommissioneeDeviceProxy(nullptr); // don't perform kWiFiNetworkSetup, we cannot send it
    CompleteGetNetworkIdentity();
    mAccess.SetCommissioneeDeviceProxy(&commissionee);
    ASSERT_EQ(CompleteWiFiNetworkSetup(), CHIP_NO_ERROR);

    const CompletionStatus & status = mAccess.AccessParams().GetCompletionStatus();
    EXPECT_EQ(status.err, CHIP_ERROR_INCORRECT_STATE);
    ASSERT_TRUE(status.failedStage.HasValue());
    EXPECT_EQ(status.failedStage.Value(), kInstallClientIdentity);

    // Cleanup is what eventually revokes the identity the retry tripped over.
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.UnregisteredIdentifier().data_equal(ByteSpan(clientIdentifier)));
    EXPECT_EQ(deviceCommissionerAccess.GetNetworkClientRegistrar(), nullptr);
}

// Cleanup is the backstop, and the only reset a second commissioning attempt is guaranteed to get:
// DeviceCommissioner::Commission(NodeId) reuses the parameters from the previous attempt without
// going through SetCommissioningParameters(), so ClearExternalBufferDependentValues() does not
// necessarily run in between. Left behind, the Network Identity would be written to a commissionee
// that may be joining a different network, and -- worse -- the possession nonce would be reused as a
// challenge against a different commissionee.
TEST_F(AutoCommissionerPDCTest, CleanupClearsPDCParameters)
{
    Configure(PDCOnlyParams(), /* supportsPDC = */ true);
    CompleteGetNetworkIdentity();
    EXPECT_EQ(CompleteWiFiNetworkSetup(), kStoppedAtPerformStep);
    ASSERT_TRUE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());
    ASSERT_TRUE(mAccess.AccessParams().GetPDCPossessionNonce().HasValue());

    mAccess.CleanupCommissioning();

    EXPECT_FALSE(mAccess.AccessParams().GetPDCNetworkIdentity().HasValue());
    EXPECT_FALSE(mAccess.AccessParams().GetPDCPossessionNonce().HasValue());
    EXPECT_FALSE(mAccess.AccessParams().GetPDCClientIdentity().HasValue());
    EXPECT_FALSE(mAccess.AccessParams().GetPDCPossessionSignature().HasValue());
}

// Cancellation and errors during either of the new stages must fall through to cleanup rather than
// advancing the flow.
TEST_F(AutoCommissionerPDCTest, NewStagesHonourStopAndError)
{
    for (CommissioningStage stage : { kGetNetworkIdentity, kInstallClientIdentity })
    {
        {
            AutoCommissioner commissioner;
            AutoCommissionerTestAccess access{ &commissioner };
            CHIP_ERROR err = CHIP_ERROR_INTERNAL;
            EXPECT_EQ(access.AccessGetNextCommissioningStageInternal(stage, err), kCleanup);
        }
        {
            AutoCommissioner commissioner;
            AutoCommissionerTestAccess access{ &commissioner };
            commissioner.StopCommissioning();
            CHIP_ERROR err = CHIP_NO_ERROR;
            EXPECT_EQ(access.AccessGetNextCommissioningStageInternal(stage, err), kCleanup);
        }
    }
}

// Being unable to reach the network's identity provider is a credentials-class failure, so the
// commissioner switches the attempt over to the secondary network rather than giving up.
TEST_F(AutoCommissionerPDCTest, GetNetworkIdentityFailureSwitchesToSecondaryNetwork)
{
    CommissioningParameters params = PDCOnlyParams();
    params.SetThreadOperationalDataset(ByteSpan());
    params.SetSupportsConcurrentConnection(true);
    ASSERT_EQ(mCommissioner.SetCommissioningParameters(params), CHIP_NO_ERROR);
    mAccess.SetCommissioner(&mDeviceCommissioner);

    ReadCommissioningInfo & info                   = mAccess.GetDeviceCommissioningInfo();
    info.network.wifi.endpoint                     = kRootEndpointId;
    info.network.wifi.supportsPerDeviceCredentials = true;
    info.network.thread.endpoint                   = 1;
    mAccess.TryPrimaryNetwork();

    CommissioningDelegate::CommissioningReport report;
    report.stageCompleted = kGetNetworkIdentity;
    // The error is swallowed and the flow is redirected to the secondary network.
    EXPECT_EQ(mCommissioner.CommissioningStepFinished(CHIP_ERROR_TIMEOUT, report), kStoppedAtPerformStep);
    EXPECT_TRUE(mAccess.TryingSecondaryNetwork());

    // We never got as far as writing a Wi-Fi configuration, so there is nothing on the commissionee
    // to remove and the flow goes straight to the secondary network.
    CHIP_ERROR err = CHIP_NO_ERROR;
    EXPECT_EQ(mAccess.AccessGetNextCommissioningStageInternal(kPrimaryOperationalNetworkFailed, err), kThreadNetworkSetup);
    EXPECT_EQ(err, CHIP_NO_ERROR);
}

// ---------------------------------------------------------------------------
// DeviceCommissioner
// ---------------------------------------------------------------------------

// PerformCommissioningStep() hangs the stage off a device proxy, but kInstallClientIdentity only
// talks to the registrar, so nothing here is ever reached.
class StubDeviceProxy : public DeviceProxy
{
public:
    void Disconnect() override {}
    NodeId GetDeviceId() const override { return 0x1234; }
    Messaging::ExchangeManager * GetExchangeManager() const override { return nullptr; }
    Optional<SessionHandle> GetSecureSession() const override { return NullOptional; }

private:
    bool IsSecureConnected() const override { return false; }
};

// Captures the outcome of a stage driven directly via PerformCommissioningStep(), and stops there:
// returning an error would send the commissioner into cleanup instead.
class RecordingCommissioningDelegate : public CommissioningDelegate
{
public:
    CHIP_ERROR SetCommissioningParameters(const CommissioningParameters &) override { return CHIP_ERROR_NOT_IMPLEMENTED; }
    const CommissioningParameters & GetCommissioningParameters() const override { return mParams; }
    void SetOperationalCredentialsDelegate(OperationalCredentialsDelegate *) override {}
    CHIP_ERROR StartCommissioning(DeviceCommissioner *, CommissioneeDeviceProxy *) override { return CHIP_ERROR_NOT_IMPLEMENTED; }

    CHIP_ERROR CommissioningStepFinished(CHIP_ERROR err, CommissioningReport report) override
    {
        mCompletions++;
        mLastError = err;
        mLastStage = report.stageCompleted;
        return CHIP_NO_ERROR;
    }

    unsigned mCompletions         = 0;
    CHIP_ERROR mLastError         = CHIP_ERROR_INTERNAL;
    CommissioningStage mLastStage = kError;

private:
    CommissioningParameters mParams;
};

// Verifying the commissionee's proof of possession, and the rollback obligation the commissioner
// takes on when it registers a Network Client Identity. None of this involves the AutoCommissioner,
// so a fixed possession nonce stands in for the generated one.
class DeviceCommissionerPDCTest : public ::testing::Test
{
protected:
    // Puts the commissioner into the state it would be in after a successful kInstallClientIdentity:
    // holding an obligation to roll mClientIdentity's registration back.
    void SimulateSuccessfulRegistration() { mAccess.SetNetworkClientRegistration(&mRegistrar, ClientIdentifier()); }

    // Parameters as they stand when kInstallClientIdentity runs: the registrar to register with, plus
    // the client identity and proof of possession the commissionee returned from kWiFiNetworkSetup.
    CommissioningParameters InstallClientIdentityParams(const TestNetworkIdentity & clientIdentity)
    {
        VerifyOrDie(clientIdentity.SignPossession(kPossessionNonce, mPossessionSignature) == CHIP_NO_ERROR);

        CommissioningParameters params;
        params.SetWiFiCredentials(WiFiCredentials(kSsid, &mRegistrar));
        params.SetPDCClientIdentity(clientIdentity.Identity());
        params.SetPDCPossessionNonce(kPossessionNonce);
        params.SetPDCPossessionSignature(mPossessionSignature.Span());
        return params;
    }

    // Runs the stage that registers a client identity with the network. The registrar completes
    // synchronously, so the stage has finished by the time this returns.
    void PerformInstallClientIdentity(CommissioningParameters & params)
    {
        mRegistrar.AcceptRegistrations();
        mCommissioner.PerformCommissioningStep(&mDeviceProxy, kInstallClientIdentity, params, &mDelegate, kRootEndpointId,
                                               NullOptional);
    }

    // The key identifier of mClientIdentity, i.e. what a rollback of its registration must name.
    ByteSpan ClientIdentifier()
    {
        VerifyOrDie(Credentials::ExtractIdentifierFromChipNetworkIdentity(
                        mClientIdentity.Identity(), Credentials::MutableCertificateKeyId(mClientIdentifier)) == CHIP_NO_ERROR);
        return ByteSpan(mClientIdentifier);
    }

    DeviceCommissioner mCommissioner{};
    DeviceCommissionerTestAccess mAccess{ &mCommissioner };
    MockNetworkIdentityRegistrar mRegistrar;
    StubDeviceProxy mDeviceProxy;
    RecordingCommissioningDelegate mDelegate;
    TestNetworkIdentity mClientIdentity;
    TestNetworkIdentity mOtherIdentity;
    Credentials::CertificateKeyIdStorage mClientIdentifier{};
    Crypto::P256ECDSASignature mPossessionSignature;
};

// The AutoCommissioner deliberately runs kWiFiNetworkSetup with PDC-only credentials even when the
// commissionee cannot do PDC, and relies on being rejected here to reach the ordinary step-failure
// path. Nothing is sent to the commissionee.
TEST_F(DeviceCommissionerPDCTest, RejectsPDCOnlyCredentialsWithoutIdentity)
{
    CommissioningParameters params;
    params.SetWiFiCredentials(WiFiCredentials(kSsid, &mRegistrar));
    ASSERT_FALSE(params.GetPDCNetworkIdentity().HasValue());

    mCommissioner.PerformCommissioningStep(&mDeviceProxy, kWiFiNetworkSetup, params, &mDelegate, kRootEndpointId, NullOptional);

    EXPECT_EQ(mDelegate.mLastStage, kWiFiNetworkSetup);
    EXPECT_EQ(mDelegate.mLastError, CHIP_ERROR_INVALID_ARGUMENT);
}

// The commissionee's proof of possession is checked before its identity is registered with the
// network, and validating the identity yields the key identifier a rollback needs.
TEST_F(DeviceCommissionerPDCTest, AcceptsValidPossessionSignature)
{
    Crypto::P256ECDSASignature signature;
    ASSERT_EQ(mClientIdentity.SignPossession(kPossessionNonce, signature), CHIP_NO_ERROR);

    Credentials::CertificateKeyIdStorage identifier{};
    EXPECT_EQ(DeviceCommissionerTestAccess::VerifyNetworkClientIdentity(
                  mClientIdentity.Identity(), signature.Span(), kPossessionNonce, Credentials::MutableCertificateKeyId(identifier)),
              CHIP_NO_ERROR);
    EXPECT_TRUE(ByteSpan(identifier).data_equal(ClientIdentifier()));
}

TEST_F(DeviceCommissionerPDCTest, RejectsPossessionSignatureOverWrongNonce)
{
    uint8_t wrongNonce[CommissioningParameters::kPossessionNonceLen] = {};
    Crypto::P256ECDSASignature signature;
    ASSERT_EQ(mClientIdentity.SignPossession(ByteSpan(wrongNonce), signature), CHIP_NO_ERROR);

    Credentials::CertificateKeyIdStorage identifier{};
    EXPECT_EQ(DeviceCommissionerTestAccess::VerifyNetworkClientIdentity(
                  mClientIdentity.Identity(), signature.Span(), kPossessionNonce, Credentials::MutableCertificateKeyId(identifier)),
              CHIP_ERROR_INVALID_SIGNATURE);
}

// A signature made by a different key must not pass, even though it is well formed.
TEST_F(DeviceCommissionerPDCTest, RejectsPossessionSignatureFromAnotherKey)
{
    Crypto::P256ECDSASignature signature;
    ASSERT_EQ(mOtherIdentity.SignPossession(kPossessionNonce, signature), CHIP_NO_ERROR);

    Credentials::CertificateKeyIdStorage identifier{};
    EXPECT_EQ(DeviceCommissionerTestAccess::VerifyNetworkClientIdentity(
                  mClientIdentity.Identity(), signature.Span(), kPossessionNonce, Credentials::MutableCertificateKeyId(identifier)),
              CHIP_ERROR_INVALID_SIGNATURE);
}

TEST_F(DeviceCommissionerPDCTest, RejectsMalformedClientIdentity)
{
    uint8_t garbage[64] = {};
    Crypto::P256ECDSASignature signature;
    ASSERT_EQ(mClientIdentity.SignPossession(kPossessionNonce, signature), CHIP_NO_ERROR);

    Credentials::CertificateKeyIdStorage identifier{};
    EXPECT_NE(DeviceCommissionerTestAccess::VerifyNetworkClientIdentity(ByteSpan(garbage), signature.Span(), kPossessionNonce,
                                                                        Credentials::MutableCertificateKeyId(identifier)),
              CHIP_NO_ERROR);
}

// Rolling back revokes the identity we registered, naming it by the key identifier we recorded when
// we took the obligation on.
TEST_F(DeviceCommissionerPDCTest, RollsBackRegistration)
{
    SimulateSuccessfulRegistration();

    mAccess.RollBackNetworkClientIdentity();

    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.UnregisteredIdentifier().data_equal(ClientIdentifier()));
    EXPECT_EQ(mAccess.GetNetworkClientRegistrar(), nullptr);
}

// Rolling back is idempotent: the first one discharges the obligation, so a second is a no-op. Not
// hypothetical -- a mid-flight rollback is always followed by the one in cleanup.
TEST_F(DeviceCommissionerPDCTest, RollbackIsIdempotent)
{
    SimulateSuccessfulRegistration();

    mAccess.RollBackNetworkClientIdentity();
    mAccess.RollBackNetworkClientIdentity();

    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
}

// Nothing to roll back if we never got as far as registering an identity.
TEST_F(DeviceCommissionerPDCTest, RollingBackWithoutARegistrationIsANoOp)
{
    mAccess.RollBackNetworkClientIdentity();

    EXPECT_EQ(mRegistrar.mUnregisterCalls, 0u);
}

// Installing an identity while the commissioner owns the rollback arms the obligation, so a later
// failure revokes exactly the identity that was registered.
TEST_F(DeviceCommissionerPDCTest, InstallingAnIdentityArmsTheRollbackByDefault)
{
    CommissioningParameters params = InstallClientIdentityParams(mClientIdentity);
    ASSERT_TRUE(params.GetManagePDCClientIdentityRollback());
    PerformInstallClientIdentity(params);

    EXPECT_EQ(mDelegate.mLastStage, kInstallClientIdentity);
    EXPECT_EQ(mDelegate.mLastError, CHIP_NO_ERROR);
    EXPECT_EQ(mRegistrar.mRegisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.RegisteredIdentity().data_equal(mClientIdentity.Identity()));
    EXPECT_EQ(mAccess.GetNetworkClientRegistrar(), &mRegistrar);

    mAccess.RollBackNetworkClientIdentity();
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.UnregisteredIdentifier().data_equal(ClientIdentifier()));
}

// A delegate that manages the registration itself still gets the client registered with the network,
// but leaves us with nothing to roll back: the identity is now that delegate's to keep or revoke.
TEST_F(DeviceCommissionerPDCTest, InstallingAnIdentityArmsNothingWhenTheDelegateManagesRollback)
{
    CommissioningParameters params = InstallClientIdentityParams(mClientIdentity);
    params.SetManagePDCClientIdentityRollback(false);
    PerformInstallClientIdentity(params);

    EXPECT_EQ(mDelegate.mLastStage, kInstallClientIdentity);
    EXPECT_EQ(mDelegate.mLastError, CHIP_NO_ERROR);
    EXPECT_EQ(mRegistrar.mRegisterCalls, 1u);
    EXPECT_TRUE(mRegistrar.RegisteredIdentity().data_equal(mClientIdentity.Identity()));
    EXPECT_EQ(mAccess.GetNetworkClientRegistrar(), nullptr);

    mAccess.RollBackNetworkClientIdentity(); // as CleanupCommissioning would on failure
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 0u);
}

// Why the decision is latched at install time rather than taken back afterwards: with the
// commissioner out of the picture nothing is ever outstanding, so a delegate that keeps several
// Network Client Identities alive is not blocked by the single-slot check on the second install.
TEST_F(DeviceCommissionerPDCTest, DelegateManagedRollbackAllowsSeveralInstalls)
{
    for (const TestNetworkIdentity * identity : { &mClientIdentity, &mOtherIdentity })
    {
        CommissioningParameters params = InstallClientIdentityParams(*identity);
        params.SetManagePDCClientIdentityRollback(false);
        PerformInstallClientIdentity(params);
        EXPECT_EQ(mDelegate.mLastError, CHIP_NO_ERROR);
    }

    EXPECT_EQ(mDelegate.mCompletions, 2u);
    EXPECT_EQ(mRegistrar.mRegisterCalls, 2u);
}

// Waiting for a revocation. Revoking a Network Client Identity is best-effort and its outcome changes
// nothing, so the commissioner normally lets the call run on unwatched. It waits only where the
// ordering is observable: removing a Wi-Fi configuration, because a retry may want to install another
// identity, against this registrar or a different one.
class DeviceCommissionerRevocationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        mCommissioner.RegisterPairingDelegate(&mPairingDelegate);
        mAccess.SetDeviceBeingCommissioned(&mDeviceProxy);

        // As after a successful kInstallClientIdentity.
        VerifyOrDie(Credentials::ExtractIdentifierFromChipNetworkIdentity(
                        mClientIdentity.Identity(), Credentials::MutableCertificateKeyId(mClientIdentifier)) == CHIP_NO_ERROR);
        mAccess.SetNetworkClientRegistration(&mRegistrar, ByteSpan(mClientIdentifier));
    }

    // Delivers a successful NetworkConfigResponse as though it had arrived during the given stage.
    void DeliverSuccessResponse(CommissioningStage stage)
    {
        mAccess.SetCommissioningStage(stage);

        NetworkCommissioning::Commands::NetworkConfigResponse::DecodableType data;
        data.networkingStatus = NetworkCommissioning::NetworkCommissioningStatusEnum::kSuccess;
        DeviceCommissionerTestAccess::OnNetworkConfigResponse(&mCommissioner, data);
    }

    class RecordingPairingDelegate : public DevicePairingDelegate
    {
    public:
        void OnCommissioningStatusUpdate(PeerId, CommissioningStage stageCompleted, CHIP_ERROR error) override
        {
            mStatusUpdates++;
            mLastStage = stageCompleted;
            mLastError = error;
        }

        unsigned mStatusUpdates       = 0;
        CommissioningStage mLastStage = kError;
        CHIP_ERROR mLastError         = CHIP_ERROR_INTERNAL;
    };

    DeviceCommissioner mCommissioner{};
    DeviceCommissionerTestAccess mAccess{ &mCommissioner };
    MockNetworkIdentityRegistrar mRegistrar;
    StubDeviceProxy mDeviceProxy;
    RecordingPairingDelegate mPairingDelegate;
    TestNetworkIdentity mClientIdentity;
    Credentials::CertificateKeyIdStorage mClientIdentifier{};
};

// A registrar that completes re-entrantly leaves nothing to wait for, so the stage is completed inline
// as it would be without PDC -- exactly once, not once here and again from the continuation. This is
// the case a warm cache produces, and the one all the other rollback tests exercise.
TEST_F(DeviceCommissionerRevocationTest, ReentrantRevocationCompletesTheStageExactlyOnce)
{
    DeliverSuccessResponse(kRemoveWiFiNetworkConfig);

    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
    EXPECT_FALSE(mRegistrar.HasPendingRevocation());
    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 1u);
    EXPECT_EQ(mPairingDelegate.mLastStage, kRemoveWiFiNetworkConfig);
    EXPECT_EQ(mPairingDelegate.mLastError, CHIP_NO_ERROR);
}

// The obligation is discharged when the revocation is handed over, not when it completes: there is
// nothing further we could do about a failure, and a second rollback must not repeat the call.
TEST_F(DeviceCommissionerRevocationTest, ObligationIsGivenUpBeforeTheRevocationCompletes)
{
    mRegistrar.DeferRevocations();

    mAccess.RollBackNetworkClientIdentity();
    ASSERT_TRUE(mRegistrar.HasPendingRevocation());

    EXPECT_EQ(mAccess.GetNetworkClientRegistrar(), nullptr);
    mAccess.RollBackNetworkClientIdentity();
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 1u);
}

// Removing the Wi-Fi configuration finishes only once the identity it was using has been given up, so
// that a retry can install another one without tripping over the one we are abandoning.
TEST_F(DeviceCommissionerRevocationTest, WiFiConfigRemovalWaitsForTheRevocation)
{
    mRegistrar.DeferRevocations();

    DeliverSuccessResponse(kRemoveWiFiNetworkConfig);
    ASSERT_EQ(mRegistrar.mUnregisterCalls, 1u);
    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 0u) << "stage completed before the revocation did";

    mRegistrar.CompleteRevocation();
    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 1u);
    EXPECT_EQ(mPairingDelegate.mLastStage, kRemoveWiFiNetworkConfig);
    EXPECT_EQ(mPairingDelegate.mLastError, CHIP_NO_ERROR);
}

// A revocation we could not complete is not a reason to fail the removal: the entry is left for an
// out-of-band audit, and the commissionee no longer has the configuration that used it either way.
TEST_F(DeviceCommissionerRevocationTest, WiFiConfigRemovalSucceedsDespiteAFailedRevocation)
{
    mRegistrar.DeferRevocations();

    DeliverSuccessResponse(kRemoveWiFiNetworkConfig);
    mRegistrar.CompleteRevocation(CHIP_ERROR_TIMEOUT);

    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 1u);
    EXPECT_EQ(mPairingDelegate.mLastError, CHIP_NO_ERROR);
}

// Removing the Thread configuration has no Network Client Identity to give up, so nothing is waited
// for -- and nothing is revoked, because a Wi-Fi registration is not ours to withdraw here.
TEST_F(DeviceCommissionerRevocationTest, ThreadConfigRemovalDoesNotWait)
{
    mRegistrar.DeferRevocations();

    DeliverSuccessResponse(kRemoveThreadNetworkConfig);

    EXPECT_EQ(mRegistrar.mUnregisterCalls, 0u);
    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 1u);
    EXPECT_EQ(mPairingDelegate.mLastStage, kRemoveThreadNetworkConfig);
}

// Giving up on a revocation we are no longer waiting for must not keep the callback a new one needs.
// A registrar holds us to one revocation at a time, so without the commissioner cancelling first the
// second one would simply be refused. Cancelling only drops our tracking of it; the RemoveClient may
// still take effect at the network, which is no worse than one we never waited for in the first place.
TEST_F(DeviceCommissionerRevocationTest, StaleRevocationIsAbandonedForANewOne)
{
    mRegistrar.DeferRevocations();
    mAccess.RollBackNetworkClientIdentity();
    ASSERT_TRUE(mRegistrar.HasPendingRevocation());

    mAccess.SetNetworkClientRegistration(&mRegistrar, ByteSpan(mClientIdentifier));
    mAccess.RollBackNetworkClientIdentity();

    EXPECT_EQ(mRegistrar.mCancelledRevocations, 1u);
    EXPECT_EQ(mRegistrar.mUnregisterCalls, 2u);
    EXPECT_TRUE(mRegistrar.HasPendingRevocation()) << "the registrar refused the second revocation";
}

// Cancelling the interactions of the attempt takes the revocation with it, per the usual Callback
// contract, so a registrar can be reclaimed synchronously rather than waited on.
TEST_F(DeviceCommissionerRevocationTest, CancellingInteractionsCancelsTheRevocation)
{
    mRegistrar.DeferRevocations();

    DeliverSuccessResponse(kRemoveWiFiNetworkConfig);
    ASSERT_TRUE(mRegistrar.HasPendingRevocation());

    mAccess.CancelCommissioningInteractions();

    EXPECT_EQ(mRegistrar.mCancelledRevocations, 1u);
    EXPECT_FALSE(mRegistrar.HasPendingRevocation());

    // The stage we were holding open is not completed behind whoever cancelled us: they are finishing
    // the attempt themselves, and completing it here would report a stage they have moved past.
    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 0u);
}

// ...and the wait must not be left lying around either, or the next revocation -- which nobody is
// waiting for -- would complete whatever stage the cancelled one was holding open.
TEST_F(DeviceCommissionerRevocationTest, CancellingAWaitDoesNotLeaveItForTheNextRevocation)
{
    mRegistrar.DeferRevocations();
    DeliverSuccessResponse(kRemoveWiFiNetworkConfig);
    mAccess.CancelCommissioningInteractions();
    ASSERT_EQ(mPairingDelegate.mStatusUpdates, 0u);

    // A fresh attempt gets as far as registering an identity, and then gives it up again.
    mAccess.SetNetworkClientRegistration(&mRegistrar, ByteSpan(mClientIdentifier));
    mAccess.RollBackNetworkClientIdentity();
    ASSERT_TRUE(mRegistrar.HasPendingRevocation());
    mRegistrar.CompleteRevocation();

    EXPECT_EQ(mPairingDelegate.mStatusUpdates, 0u) << "a stage was completed by a revocation nobody waited for";
}
} // namespace
