-- SPDX-License-Identifier: MPL-2.0
-- Vörðr Gatekeeper - fail-open regression tests
--
-- Standalone driver (no AUnit in this repo): prints PASS/FAIL per assertion
-- and exits non-zero if any assertion fails, so it doubles as a mutation
-- oracle.
--
-- Built via gnatmake over the COMPILABLE closure
--   {gatekeeper, threshold_signatures, container_policy}.
-- It deliberately does NOT touch oci_parser / policy_interface: those units do
-- not compile under the local GNAT because of a pre-existing SPARK error
-- (E0015: a function may not have a parameter of mode "in out"/"out") in
-- oci_parser.ads. Fixing E0015 is fix/ada-build's scope; the parser fail-open
-- test that belongs here (test_parser_failopen.adb) is therefore compile-
-- blocked and cannot run until that lands.

pragma SPARK_Mode (Off);  --  test driver uses Text_IO; not part of proved core

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Container_Policy;      use Container_Policy;
with Threshold_Signatures; use Threshold_Signatures;
with Gatekeeper;           use Gatekeeper;

procedure Test_Failopen is

   Failures : Natural := 0;

   procedure Check (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Put_Line ("PASS: " & Name);
      else
         Put_Line ("FAIL: " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   --  A signer id that is NOT the null signer.
   Real_Signer : constant Signer_ID := (others => 'A');

   --  A share whose Valid flag has been asserted true. Valid is a plain record
   --  field; nothing derived it from a signature, so an attacker can set it.
   Asserted_Share : constant Signature_Share :=
     (Signer    => Real_Signer,
      Signature => (others => 'S'),
      Valid     => True);

begin
   -------------------------------------------------------------------------
   --  FAIL-OPEN REGRESSION: Verify_Share must FAIL CLOSED.
   --
   --  The input is exactly what the OLD body returned True for: Valid => True,
   --  Signer /= Null_Signer_ID, non-empty Message.
   --    OLD: return Share.Valid and then Share.Signer /= Null_Signer_ID => True
   --    NEW: return False  (no crypto implemented -> deny)
   --  Reverting the fix flips this assertion red: that IS the mutation-check.
   -------------------------------------------------------------------------
   Check ("Verify_Share DENIES an unverified but Valid-flagged share",
          Verify_Share (Asserted_Share, "message-to-authorize") = False);

   -------------------------------------------------------------------------
   --  CONTROL (admit) #1: a genuinely-secure config validates as Valid.
   --  Guards against a suite that would "pass by denying everything".
   -------------------------------------------------------------------------
   Check ("Default_Config validates as Valid (admit control)",
          Validate_Configuration (Default_Config) = Valid);

   -------------------------------------------------------------------------
   --  CONTROL (admit) #2: a full gatekeeper flow still reaches Allow for a
   --  valid config once the threshold is met. Verify_Share's fix does not
   --  touch this path (Add_Share trusts Share.Valid and never calls it), so
   --  the gate must still ADMIT here.
   -------------------------------------------------------------------------
   declare
      Req      : Authorization_Request :=
        Create_Request (Default_Config, Threshold => 1, Signers => 1);
      Decision : Gatekeeper_Decision;
   begin
      Submit_Signature (Req, Asserted_Share, Decision);
      Check ("Gatekeeper ADMITS a valid request at threshold (Allow)",
             Decision = Allow);
   end;

   -------------------------------------------------------------------------
   --  CONTROL (deny): a genuinely-unsafe config is rejected (not Valid).
   --  Proves the gate distinguishes safe from unsafe -- it does not admit all.
   -------------------------------------------------------------------------
   declare
      Bad : Container_Config := Default_Config;
   begin
      Bad.Is_Privileged := False;
      Bad.Capabilities (CAP_SYS_ADMIN) := True;  --  dangerous, unprivileged
      Check ("SYS_ADMIN without privilege is REJECTED (Invalid_Capabilities)",
             Validate_Configuration (Bad) = Invalid_Capabilities);
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line ("TESTS FAILED:" & Natural'Image (Failures));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Failopen;
