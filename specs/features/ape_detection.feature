# E9APE Detection - BDD Specification
# Behavior-Driven: describes WHAT the system does, not HOW
# Convention: Gherkin with cosmic naming

Feature: APE Binary Detection
  As a binary patching tool
  I need to identify APE (Actually Portable Executable) binaries
  So that I can apply patches correctly to all format layers

  Background:
    Given the e9patch analysis engine is initialized
    And APE format detection is enabled

  # ── Standard APE Detection ───────────────────────────────────────

  Scenario: Detect standard Cosmopolitan APE binary
    Given a binary file starting with "MZqFpD"
    And containing a valid ELF64 header at offset 64
    And containing a PE signature at the DOS e_lfanew offset
    When I run APE detection
    Then the result should be "APE detected"
    And the format should be E9_FORMAT_APE
    And both ELF and PE views should be populated

  Scenario: Detect APE binary with shell script header
    Given a binary file starting with "#!/bin/sh"
    And containing "MZqFpD" after the shell header
    And containing valid ELF and PE structures
    When I run APE detection
    Then the result should be "APE detected"
    And shell_offset should be 0
    And shell_size should be greater than 0

  Scenario: Detect APE binary with ZipOS
    Given a valid APE binary
    And containing a ZIP End of Central Directory record
    When I run APE detection and parsing
    Then zipos_start should be set
    And zipos_central_dir should be set
    And zipos_num_entries should be greater than 0

  # ── Non-APE Rejection ────────────────────────────────────────────

  Scenario: Reject standard ELF binary
    Given a binary file starting with ELF magic "\x7fELF"
    And NOT containing "MZqFpD" anywhere
    When I run APE detection
    Then the result should be "not APE"
    And the format should be E9_FORMAT_ELF

  Scenario: Reject standard PE binary
    Given a binary file starting with "MZ" (standard DOS stub)
    And NOT starting with "MZqFpD"
    When I run APE detection
    Then the result should be "not APE"
    And the format should be E9_FORMAT_PE

  Scenario: Reject truncated binary
    Given only 4 bytes of data
    When I run APE detection
    Then the result should be "incomplete"
    And no format should be assigned

  # ── Edge Cases ───────────────────────────────────────────────────

  Scenario: Handle APE with minimal PE (ELF-dominant)
    Given an APE binary where PE sections are stubs
    And ELF is the primary executable format
    When I parse the APE structure
    Then elf_size should be greater than pe_size
    And patches should default to ELF view

  Scenario: Handle APE with full PE (dual-native)
    Given an APE binary with complete PE and ELF sections
    And both are functional native executables
    When I parse the APE structure
    Then sync_elf_pe should default to true
    And patches to ELF should reflect in PE view
