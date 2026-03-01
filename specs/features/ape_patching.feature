# E9APE Patching - BDD Specification
# Behavior-Driven: describes WHAT the system does, not HOW
# Convention: Gherkin with cosmic naming

Feature: APE Binary Patching
  As a binary rewriting tool
  I need to patch APE binaries consistently across all format layers
  So that the patched binary remains valid as ELF, PE, and ZipOS

  Background:
    Given a valid APE binary is loaded
    And APE parsing has completed successfully
    And sync_elf_pe is enabled

  # ── Basic Patching ───────────────────────────────────────────────

  Scenario: Patch code at ELF virtual address
    Given a function at ELF virtual address 0x401000
    And the function is in a mapped ELF segment
    And the same bytes exist in a PE section
    When I apply a 5-byte patch at 0x401000
    Then the patch should be written to the file
    And the ELF view should reflect the patch
    And the PE view should reflect the same patch
    And the file should remain a valid APE

  Scenario: Patch data section
    Given a global variable at ELF address 0x404000
    And the variable is in the .data segment
    When I apply a 4-byte patch at 0x404000
    Then the patch should succeed
    And the data should be updated in both ELF and PE views

  # ── Address Translation ──────────────────────────────────────────

  Scenario: Translate ELF vaddr to file offset
    Given an ELF program header with:
      | p_vaddr  | p_offset | p_filesz |
      | 0x400000 | 0x1000   | 0x5000   |
    When I translate ELF address 0x401234 to file offset
    Then the result should be 0x2234

  Scenario: Translate PE RVA to file offset
    Given a PE section header with:
      | VirtualAddress | PointerToRawData | SizeOfRawData |
      | 0x1000         | 0x400            | 0x2000        |
    When I translate PE RVA 0x1500 to file offset
    Then the result should be 0x900

  Scenario: Fail translation for unmapped address
    Given ELF segments do not cover address 0x800000
    When I translate ELF address 0x800000 to file offset
    Then the translation should fail
    And the error should indicate "address not mapped"

  # ── ELF/PE Synchronization ───────────────────────────────────────

  Scenario: Synchronized patch updates both views
    Given sync_elf_pe is true
    And address 0x401000 maps to file offset 0x1000 in ELF
    And address 0x401000 maps to file offset 0x1000 in PE (same)
    When I patch via ELF view
    Then only one write should occur (at file offset 0x1000)

  Scenario: Synchronized patch to different file offsets
    Given sync_elf_pe is true
    And ELF address 0x401000 maps to file offset 0x1000
    And PE RVA 0x1000 maps to file offset 0x2000
    When I patch via ELF view at 0x401000
    Then the patch should be written to file offset 0x1000
    And the corresponding PE location should also be patched
    And both views should show identical bytes

  Scenario: Disable sync for ELF-only patch
    Given sync_elf_pe is false
    When I patch via ELF view at 0x401000
    Then only the ELF view should be updated
    And the PE view should retain original bytes

  # ── ZipOS Handling ───────────────────────────────────────────────

  Scenario: Patch does not corrupt ZipOS
    Given the patch target is before zipos_start
    And preserve_zipos is true
    When I apply a patch
    Then the ZipOS central directory should remain valid
    And all ZIP entries should remain accessible

  Scenario: Warn on patch overlapping ZipOS
    Given a patch target overlaps zipos_start
    When I attempt to apply the patch
    Then a warning should be issued
    And the patch should proceed (ZipOS may be invalidated)

  # ── Error Handling ───────────────────────────────────────────────

  Scenario: Reject patch beyond file bounds
    Given the APE file is 100KB
    When I attempt to patch at file offset 200KB
    Then the patch should be rejected
    And the error should indicate "offset out of bounds"

  Scenario: Reject patch with size overflow
    Given 10 bytes remaining at target offset
    When I attempt a 20-byte patch
    Then the patch should be rejected
    And the error should indicate "patch exceeds segment"
