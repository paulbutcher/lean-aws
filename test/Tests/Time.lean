/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Aws.Sigv4

/-!
Construction already keeps the credential scope and the timestamp in step. What it does not give is
the width of each field, which is what the theorems here fix: a signature is rejected just as
firmly by a date of seven characters as by the wrong date.
-/

namespace Tests.Time
open Aws.Sigv4 Aws.Sigv4.Timestamp

/-- A two-digit field is two characters whatever it is given, so a month or an hour below ten is
written `04` and not `4`. A field of the wrong width moves every field after it.

Nothing restricts `n`: the string is built from two characters for every natural, so above 99,
where the value is truncated rather than represented, the width is unchanged. -/
theorem length_pad2 (n : Nat) : (pad2 n).length = 2 := by simp [pad2]

/-- The year field is four characters, which is what fixes the width of the date stamp it opens.

Again `n` ranges over every natural, and the string is built from four characters, so a year of
five digits truncates rather than widening the field. -/
theorem length_pad4 (n : Nat) : (pad4 n).length = 4 := by simp [pad4]

/-- The date half of the credential scope is eight characters, `YYYYMMDD`. The scope is signed and
compared as text, so an eight-character field carrying seven is refused as firmly as a wrong date.

Every `Timestamp` is covered, and so every instant `civil` can be given a day count for. The four
characters of the year and the two each of month and day come from the theorems above; only their
sum is claimed, not that the fields are the date. -/
theorem length_dateStamp (t : Timestamp) : t.dateStamp.length = 8 := by
  simp [Timestamp.dateStamp, length_pad2, length_pad4]

/-- The `x-amz-date` header, which is also the second line of the string to sign, is sixteen
characters, `YYYYMMDDTHHMMSSZ`. AWS reads it by position, so a field of the wrong width is read as
part of the next one.

Every `Timestamp` is covered. The eight of `dateStamp`, the `T` and the `Z`, and two characters
each for hours, minutes and seconds come to sixteen; that they appear in that order is what the
checks below cover. -/
theorem length_amzDate (t : Timestamp) : t.amzDate.length = 16 := by
  simp [Timestamp.amzDate, length_pad2, length_dateStamp]
  rfl

/-- The civil-date arithmetic, at the instants where a wrong one shows. Every expected value here
was confirmed against an independent implementation rather than worked out by hand twice. -/
public def checks : List (String × Bool) :=
  [ ("the epoch itself", (Timestamp.mk 0).amzDate == "19700101T000000Z"),
    ("the last second of a day", (Timestamp.mk 86399).amzDate == "19700101T235959Z"),
    -- 2000 is a leap year because it divides by 400, which is the rule a naive implementation
    -- gets wrong in the direction that looks right for a century.
    ("29 February 2000", (Timestamp.mk 951782400).amzDate == "20000229T000000Z"),
    ("29 February 2024", (Timestamp.mk 1709164800).amzDate == "20240229T000000Z"),
    -- 2100 divides by 100 and not by 400, so it is not a leap year and 29 February does not exist.
    ("1 March 2100", (Timestamp.mk 4107542400).amzDate == "21000301T000000Z") ]

end Tests.Time
