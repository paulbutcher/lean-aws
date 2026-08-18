/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aws.Sigv4

/-!
`amzDate` is defined as `dateStamp` followed by the time, so the credential scope and the timestamp
cannot disagree by construction; deriving them from separate clock reads is what would admit a
signature that fails for one second a day. What construction does not give is the width of each
field, which is what the theorems here fix: a signature is rejected just as firmly by a date of
seven characters as by the wrong date.
-/

namespace Tests.Time
open Aws.Sigv4 Aws.Sigv4.Timestamp

theorem length_pad2 (n : Nat) : (pad2 n).length = 2 := by simp [pad2]

theorem length_pad4 (n : Nat) : (pad4 n).length = 4 := by simp [pad4]

theorem length_dateStamp (t : Timestamp) : t.dateStamp.length = 8 := by
  simp [Timestamp.dateStamp, length_pad2, length_pad4]

theorem length_amzDate (t : Timestamp) : t.amzDate.length = 16 := by
  simp [Timestamp.amzDate, length_pad2, length_dateStamp]
  rfl

/-- The civil-date arithmetic, at the instants where a wrong one shows. Every expected value here
was confirmed against an independent implementation rather than worked out by hand twice. -/
def checks : List (String × Bool) :=
  [ ("the epoch itself", (Timestamp.mk 0).amzDate == "19700101T000000Z"),
    ("the last second of a day", (Timestamp.mk 86399).amzDate == "19700101T235959Z"),
    -- 2000 is a leap year because it divides by 400, which is the rule a naive implementation
    -- gets wrong in the direction that looks right for a century.
    ("29 February 2000", (Timestamp.mk 951782400).amzDate == "20000229T000000Z"),
    ("29 February 2024", (Timestamp.mk 1709164800).amzDate == "20240229T000000Z"),
    -- 2100 divides by 100 and not by 400, so it is not a leap year and 29 February does not exist.
    ("1 March 2100", (Timestamp.mk 4107542400).amzDate == "21000301T000000Z") ]

end Tests.Time
