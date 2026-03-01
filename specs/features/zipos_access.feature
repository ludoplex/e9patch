# E9APE ZipOS Access - BDD Specification
# Behavior-Driven: describes WHAT the system does, not HOW
# Convention: Gherkin with cosmic naming

Feature: ZipOS Embedded Filesystem Access
  As a binary patching tool
  I need to read files from APE's embedded ZipOS filesystem
  So that I can access bundled assets, configs, and WASM modules

  Background:
    Given a valid APE binary with ZipOS
    And the ZipOS central directory is parsed

  # ── File Listing ─────────────────────────────────────────────────

  Scenario: List all ZipOS entries
    Given the APE contains 5 embedded files
    When I call e9_ape_zipos_list
    Then I should receive an array of 5 entries
    And each entry should have name, size, and compression info

  Scenario: List includes directories
    Given the APE contains "/usr/share/binaryen/"
    When I list ZipOS entries
    Then I should see an entry with is_directory=true
    And the name should be "/usr/share/binaryen/"

  # ── File Reading ─────────────────────────────────────────────────

  Scenario: Read uncompressed file from ZipOS
    Given the APE contains "/etc/config.ini" stored uncompressed
    When I call e9_ape_zipos_read for "/etc/config.ini"
    Then I should receive the file contents
    And the size should match uncompressed_size

  Scenario: Read compressed file from ZipOS
    Given the APE contains "/lib/binaryen.wasm" with DEFLATE compression
    When I call e9_ape_zipos_read for "/lib/binaryen.wasm"
    Then the file should be decompressed
    And I should receive valid WASM bytes starting with 0x00 0x61 0x73 0x6D

  Scenario: Verify CRC32 on read
    Given the APE contains a file with CRC32 0xDEADBEEF
    When I read the file
    Then the computed CRC32 should match
    And the read should succeed

  Scenario: Detect CRC32 mismatch (corrupt file)
    Given the APE contains a file with mismatched CRC32
    When I read the file
    Then the read should fail
    And the error should indicate "CRC mismatch"

  # ── File Existence Check ─────────────────────────────────────────

  Scenario: Check if file exists in ZipOS
    Given the APE contains "/lib/binaryen.wasm"
    When I call e9_ape_zipos_exists for "/lib/binaryen.wasm"
    Then the result should be true

  Scenario: Check non-existent file
    When I call e9_ape_zipos_exists for "/nonexistent.txt"
    Then the result should be false

  # ── Binaryen WASM Loading ────────────────────────────────────────

  Scenario: Load Binaryen from ZipOS for WAMR
    Given the APE contains "/lib/binaryen.wasm"
    When I initialize Binaryen with E9_BINARYEN_WASM backend
    Then e9_ape_zipos_read should be called for "/lib/binaryen.wasm"
    And the WASM module should be loaded into WAMR
    And e9_binaryen_is_ready should return true

  Scenario: Fallback when Binaryen WASM missing
    Given the APE does NOT contain "/lib/binaryen.wasm"
    When I initialize Binaryen with E9_BINARYEN_WASM backend
    Then initialization should fail gracefully
    And e9_binaryen_get_error should indicate "binaryen.wasm not found"

  # ── Memory Management ────────────────────────────────────────────

  Scenario: Free ZipOS entry list
    Given I have called e9_ape_zipos_list
    When I call e9_ape_zipos_free_list
    Then all entry memory should be released
    And no memory leaks should occur

  Scenario: Free read buffer
    Given I have called e9_ape_zipos_read
    When I free the returned buffer
    Then the memory should be released
    And no double-free should occur
