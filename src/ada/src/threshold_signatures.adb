-- SPDX-License-Identifier: MPL-2.0
-- Vörðr Gatekeeper - Threshold Signature Implementation
-- SPARK-proved (k,n) threshold authorization

pragma SPARK_Mode (On);

package body Threshold_Signatures is

   --  Create a new (k,n) threshold scheme
   function Create_Scheme (
      Threshold     : Positive;
      Total_Signers : Positive
   ) return Threshold_Scheme
   is
      Result : Threshold_Scheme;
   begin
      Result.Threshold     := Threshold;
      Result.Total_Signers := Total_Signers;
      Result.Share_Count   := 0;
      Result.Shares        := (others => Null_Share);
      return Result;
   end Create_Scheme;

   --  Check if a signer has already contributed
   function Has_Signer (
      Scheme : Threshold_Scheme;
      Signer : Signer_ID
   ) return Boolean
   is
   begin
      for I in Share_Index'First .. Share_Index'Val (Scheme.Share_Count) loop
         if Scheme.Shares (I).Signer = Signer then
            return True;
         end if;
         pragma Loop_Invariant (I <= Share_Index'Val (Scheme.Share_Count));
      end loop;
      return False;
   end Has_Signer;

   --  Add a signature share to the scheme
   procedure Add_Share (
      Scheme : in Out Threshold_Scheme;
      Share  : Signature_Share;
      Result : out Authorization_Result
   )
   is
   begin
      --  Validate scheme state
      if not Is_Valid_Scheme (Scheme) then
         Result := Invalid_Scheme;
         return;
      end if;

      --  Check if scheme is already full
      if Scheme.Share_Count >= Scheme.Total_Signers then
         Result := Scheme_Full;
         return;
      end if;

      --  Validate the share
      if not Share.Valid then
         Result := Invalid_Signature;
         return;
      end if;

      --  Check for duplicate signer
      if Has_Signer (Scheme, Share.Signer) then
         Result := Duplicate_Signer;
         return;
      end if;

      --  Add the share
      Scheme.Share_Count := Scheme.Share_Count + 1;
      Scheme.Shares (Share_Index'Val (Scheme.Share_Count)) := Share;

      --  Check if threshold is now reached
      if Scheme.Share_Count >= Scheme.Threshold then
         Result := Authorized;
      else
         Result := Pending;
      end if;
   end Add_Share;

   --  Reset scheme (clear all shares)
   procedure Reset_Scheme (Scheme : in Out Threshold_Scheme)
   is
   begin
      Scheme.Share_Count := 0;
      Scheme.Shares := (others => Null_Share);
   end Reset_Scheme;

   --  Verify a signature share
   --  NOTE: Actual cryptographic verification delegated to external library
   --  This is a specification stub that assumes valid signature format
   function Verify_Share (
      Share   : Signature_Share;
      Message : String
   ) return Boolean
   is
      pragma Unreferenced (Share);
      pragma Unreferenced (Message);
   begin
      --  FAIL CLOSED. No cryptographic verification is implemented here yet.
      --
      --  The previous body returned
      --     Share.Valid and then Share.Signer /= Null_Signer_ID
      --  i.e. it approved any share whose Valid flag was set and whose signer
      --  was non-null, while ignoring Message entirely (pragma Unreferenced).
      --  Valid is an attacker-assertable record field, not a derived fact, so
      --  that stub verified NOTHING: it was a crypto gate that could not fail.
      --
      --  A verifier that cannot verify must DENY, not approve. Returning False
      --  means that the moment this is wired into Add_Share (which today trusts
      --  Share.Valid directly and never calls this function -- see PR notes),
      --  the path fails closed until real Ed25519 verification against Message
      --  (libsodium/OpenSSL) replaces this body.
      return False;
   end Verify_Share;

end Threshold_Signatures;
