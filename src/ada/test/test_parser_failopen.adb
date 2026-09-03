-- SPDX-License-Identifier: MPL-2.0
-- Vörðr Gatekeeper - OCI parser fail-open regression test
--
-- COMPILE-BLOCKED as of this commit. It withs OCI_Parser, whose spec
-- (oci_parser.ads) does not compile under the current GNAT:
--
--   oci_parser.ads:67: error: function cannot have parameter of mode
--                       "out" or "in out" in SPARK [E0015]
--   (and the same at :75, :82, :89, :90, :91, :98)
--
-- Fixing E0015 is fix/ada-build's scope (it ripples through every parser call
-- site and another session holds uncommitted work on it). This test is written
-- now so that the moment E0015 lands, the parser fail-open is guarded. No
-- mutation-check is claimed for it here, because it cannot be built or run in
-- this environment -- honest red.
--
-- What it proves once runnable:
--   * BEFORE the Parse_Oci_Config fix: Parse_Oci_Config ("aaaa", 4).Status is
--     Parse_OK -> the gate reports garbage as parseable (fail-open).
--   * AFTER the fix: it is Parse_Invalid_Json (fail-closed), while the two
--     inputs the Rust FFI suite asserts must be ADMITTED still parse Parse_OK.

pragma SPARK_Mode (Off);

with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;
with OCI_Parser;       use OCI_Parser;

procedure Test_Parser_Failopen is

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

   --  Garbage: non-empty, in-length, but not a JSON object.
   Garbage : constant String := "aaaa";

   --  Admit control #1: the exact string gatekeeper.rs:415 asserts is accepted.
   Valid_A : constant String := "{""process"": {""user"": {""uid"": 1000}}}";

   --  Admit control #2: a config that omits root.readonly (still well-formed).
   Valid_B : constant String := "{""process"": {""user"": {""uid"": 0}}}";

begin
   --  FAIL-CLOSED: unparseable input must NOT be reported Parse_OK.
   Check ("garbage input is rejected (Parse_Invalid_Json, not Parse_OK)",
          Parse_Oci_Config (Garbage, Garbage'Length).Status
            = Parse_Invalid_Json);

   --  ADMIT controls: well-formed objects still parse OK (fix is not too strict).
   Check ("valid object A is admitted (Parse_OK)",
          Parse_Oci_Config (Valid_A, Valid_A'Length).Status = Parse_OK);
   Check ("valid object B is admitted (Parse_OK)",
          Parse_Oci_Config (Valid_B, Valid_B'Length).Status = Parse_OK);

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line ("TESTS FAILED:" & Natural'Image (Failures));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Parser_Failopen;
