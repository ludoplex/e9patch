Feature: E9 Live Reload - Hot Patching APE Binaries
  As a developer working with APE binaries
  I want to see my C source changes reflected in real-time
  So that I can iterate quickly without restarting the application

  Background:
    Given an APE binary "target.com" is loaded
    And live reload is initialized with source directory "src/"
    And the compiler "cosmocc" is available

  # ── File Watching ─────────────────────────────────────────────────────

  Scenario: Detect C source file changes
    Given a source file "src/main.c" exists
    When I modify "src/main.c"
    Then a FILE_CHANGE event should be emitted
    And the event should contain the file path "src/main.c"

  Scenario: Ignore non-C files
    Given a source file "src/README.md" exists
    When I modify "src/README.md"
    Then no FILE_CHANGE event should be emitted

  # ── Compilation ───────────────────────────────────────────────────────

  Scenario: Successful incremental compilation
    Given a valid C source file "src/func.c"
    When a FILE_CHANGE event is detected for "src/func.c"
    Then a COMPILE_START event should be emitted
    And cosmocc should be invoked with "-c src/func.c"
    And a COMPILE_DONE event should be emitted
    And the object file should be cached in ".e9cache/"

  Scenario: Compilation failure handling
    Given an invalid C source file "src/broken.c" with syntax errors
    When a FILE_CHANGE event is detected for "src/broken.c"
    Then a COMPILE_ERROR event should be emitted
    And the error message should contain the compiler output
    And no patches should be generated

  # ── Object Diffing ────────────────────────────────────────────────────

  Scenario: Generate patches from object diff
    Given a cached object "func.c.o" from previous compilation
    And a new object "func.c.new.o" with changes to function "process_data"
    When Binaryen diffs the two objects
    Then a PATCH_GENERATED event should be emitted
    And the patch should target function "process_data"
    And the patch should contain the address and replacement bytes

  Scenario: No patches when no functional changes
    Given a cached object "func.c.o"
    And a new object "func.c.new.o" with only whitespace changes
    When Binaryen diffs the two objects
    Then no PATCH_GENERATED event should be emitted
    And the status should indicate "No changes detected"

  # ── APE Patching ──────────────────────────────────────────────────────

  Scenario: Apply patch via PE RVA
    Given a patch targeting PE RVA 0x11234
    And the APE has .text section at file offset 0x11000 with RVA 0x11000
    When the patch is applied
    Then the file offset should be calculated as 0x11234
    And the bytes should be written to the memory-mapped binary
    And a PATCH_APPLIED event should be emitted

  Scenario: Apply patch to .rdata section
    Given a patch targeting PE RVA 0x2F100
    And the APE has .rdata section at file offset 0x2F000 with RVA 0x2F000
    When the patch is applied
    Then the file offset should be calculated as 0x2F100
    And the patch should succeed

  Scenario: Reject patch overlapping ZipOS
    Given an APE with ZipOS starting at offset 0x60000
    And a patch targeting file offset 0x60010
    When the patch is applied
    Then a warning should be emitted about ZipOS overlap
    And the patch may proceed with user acknowledgment

  # ── Instruction Cache ─────────────────────────────────────────────────

  Scenario: Flush icache after code patch
    Given a patch was applied to executable .text section
    When the patch is finalized
    Then e9wasm_flush_icache should be called
    And the flushed range should cover the patched bytes

  # ── Self-Patching ─────────────────────────────────────────────────────

  Scenario: Self-patching the running executable
    Given live reload is initialized with target NULL (self)
    When the executable path is determined via /proc/self/exe
    Then the running APE should be memory-mapped
    And patches should be applied in-place
    And execution should continue with the new code

  # ── Statistics ────────────────────────────────────────────────────────

  Scenario: Track live reload statistics
    Given live reload has processed multiple source changes
    When I query the statistics
    Then I should see:
      | Metric              | Type    |
      | changes_detected    | counter |
      | patches_generated   | counter |
      | patches_applied     | counter |
      | patches_failed      | counter |
      | total_bytes_patched | counter |
      | last_change_time    | timestamp |
      | last_patch_time     | timestamp |

  # ── Patch Reversion ───────────────────────────────────────────────────

  Scenario: Revert a previously applied patch
    Given patch #1 was applied at offset 0x11234
    And the original bytes were saved
    When I revert patch #1
    Then the original bytes should be restored
    And a PATCH_REVERTED event should be emitted
    And the instruction cache should be flushed

  # ── Error Handling ────────────────────────────────────────────────────

  Scenario: Handle missing compiler gracefully
    Given the compiler "cosmocc" is not in PATH
    When I call e9_livereload_compiler_available()
    Then it should return false
    And compilation attempts should fail with a clear error message

  Scenario: Handle unmappable target
    Given a target file that does not exist
    When I initialize live reload with that target
    Then initialization should fail with error "Cannot open target"
    And e9_livereload_get_error() should return the error message
