package jinguissl_core.tests

import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.perf.*

@Test
public class CorePerfTestSuite {
    @TestCase
    public func testBenchConfigNormalizesAndRetainsInputs(): Unit {
        let config = BenchConfig(" digest ", warmupRounds: 0, samples: 3)
        @Assert(config.name, "digest")
        @Assert(config.warmupRounds, 0)
        @Assert(config.samples, 3)
    }

    @TestCase
    public func testBenchConfigRejectsInvalidInputs(): Unit {
        try {
            _ = BenchConfig(" ")
            @Fail("BenchConfig should reject an empty name")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = BenchConfig("digest", warmupRounds: -1)
            @Fail("BenchConfig should reject negative warmup rounds")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = BenchConfig("digest", samples: 0)
            @Fail("BenchConfig should reject zero samples")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }
    }

    @TestCase
    public func testBenchSummaryFormattingIsInspectable(): Unit {
        let summary = BenchSummary(
            "digest", 1, 3, 100,
            1.0, 2.0, 3.0, 2.0, 2.0, 3.0
        )
        let formatted = benchFormatSummary(summary)
        @Assert(formatted.contains("name=digest"), true)
        @Assert(formatted.contains("samples=3"), true)

        let stable = BenchStableSummary(summary, 2, true, 3.5)
        let stableFormatted = benchFormatStableSummary(stable)
        @Assert(stableFormatted.contains("stable=true"), true)
        @Assert(stableFormatted.contains("attempts=2"), true)
    }

    @TestCase
    public func testBenchCpuPinningCanBeExplicitlyDisabled(): Unit {
        let binding = benchTryPinCurrentThread(-1)
        @Assert(binding.requested, false)
        @Assert(binding.applied, false)
        @Assert(binding.detail, "cpu pinning is not requested")
    }
}
