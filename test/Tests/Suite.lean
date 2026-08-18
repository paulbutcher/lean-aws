/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aws.Sigv4

/-!
AWS's published Signature Version 4 test suite.

The cases are committed rather than fetched, so the suite fails when this library does and not
when a network does. They were taken from the copy vendored in `mhart/aws4`, AWS having retired
the download its own documentation still points at.

Each case is checked at all three stages. A mismatch in the signature says only that something is
wrong; a mismatch in the canonical request says where, and the canonical request and string to
sign are text rather than a digest, so they can be read.

Two reductions were made in turning a raw HTTP request into the data this library takes, and both
are recorded here rather than left to be noticed:

* `get-header-value-multiline` folds its continuation lines into repeated headers. Unfolding is
  HTTP parsing and happens above this library; AWS joins the folded values with commas, which is
  what repeated headers of the same name already mean here.
* `post-sts-header-after` carries no security token in its request, because the case exists to
  describe an SDK that adds the token after signing. This library signs a token whenever the
  credentials carry one, so the case is run as what its request actually says.
-/

namespace Tests.Suite
open Aws.Sigv4

private structure Case where
  name : String
  request : Request
  sessionToken : Option String := none
  canonical : String
  stringToSign : String
  authorization : String

private def instant : Timestamp := ⟨1440938160⟩

private def scope : SigningScope := { region := "us-east-1", service := "service" }

private def credentialsFor (token : Option String) : Credentials :=
  { accessKeyId := "AKIDEXAMPLE"
    secretAccessKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    sessionToken := token }

private def cases : List Case :=
  [
    { name := "get-header-key-duplicate"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("My-Header1", "value2"), ("My-Header1", "value2"), ("My-Header1", "value1")]
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value2,value2,value1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\ndc7f04a3abfde8d472b0ab1a418b741b7c67174dad1551b4117b15527fbe966c"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea" },
    { name := "get-header-value-multiline"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("My-Header1", "value1"), ("My-Header1", "value2"), ("My-Header1", "value3")]
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value1,value2,value3\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nb7b6cbfd8a0430b78891e986784da2630c8a135a8595cec25b26ea94f926ee55"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=ba17b383a53190154eb5fa66a1b836cc297cc0a3d70a5d00705980573d8ff790" },
    { name := "get-header-value-order"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("My-Header1", "value4"), ("My-Header1", "value1"), ("My-Header1", "value3"), ("My-Header1", "value2")]
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value4,value1,value3,value2\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n31ce73cd3f3d9f66977ad3dd957dc47af14df92fcd8509f59b349e9137c58b86"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01" },
    { name := "get-header-value-trim"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("My-Header1", " value1"), ("My-Header2", " \"a   b   c\"")]
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nmy-header2:\"a b c\"\nx-amz-date:20150830T123600Z\n\nhost;my-header1;my-header2;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\na726db9b0df21c14f559d0a978e563112acb1b9e05476f0a6a1c7d68f28605c7"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;my-header2;x-amz-date, Signature=acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736" },
    { name := "get-unreserved"
      request :=
        { method := "GET"
          path := "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n6a968768eefaa713e2a6b16b589a8ea192661f098f37349f4e2c0082757446f9"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f" },
    { name := "get-utf8"
      request :=
        { method := "GET"
          path := "/ሴ"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/%E1%88%B4\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n2a0a97d02205e45ce2e994789806b19270cfbbb0921b278ccf58f5249ac42102"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85" },
    { name := "get-vanilla"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    { name := "get-vanilla-empty-query-key"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := [("Param1", "value1")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\nParam1=value1\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n1e24db194ed7d0eec2de28d7369675a243488e08526e8c1c73571282f7c517ab"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb" },
    { name := "get-vanilla-query"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    { name := "get-vanilla-query-order-key"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := [("Param1", "value2"), ("Param1", "Value1")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\nParam1=Value1&Param1=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n704b4cef673542d84cdff252633f065e8daeba5f168b77116f8b1bcaf3d38f89"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=eedbc4e291e521cf13422ffca22be7d2eb8146eecf653089df300a15b2382bd1" },
    { name := "get-vanilla-query-order-key-case"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := [("Param2", "value2"), ("Param1", "value1")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\nParam1=value1&Param2=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500" },
    { name := "get-vanilla-query-order-value"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := [("Param1", "value2"), ("Param1", "value1")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\nParam1=value1&Param1=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nc968629d70850097a2d8781c9bf7edcb988b04cac14cca9be4acc3595f884606"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5772eed61e12b33fae39ee5e7012498b51d56abc0abb7c60486157bd471c4694" },
    { name := "get-vanilla-query-unreserved"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := [("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nc30d4703d9f799439be92736156d47ccfb2d879ddf56f5befa6d1d6aab979177"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197" },
    { name := "get-vanilla-utf8-query"
      request :=
        { method := "GET"
          path := "/"
          host := "example.amazonaws.com"
          query := [("ሴ", "bar")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n%E1%88%B4=bar\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\neb30c5bed55734080471a834cc727ae56beb50e5f39d1bff6d0d38cb192a7073"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=2cdec8eed098649ff3a119c94853b13c643bcf08f8b0a1d91e12c9027818dd04" },
    { name := "normalize-path/get-relative"
      request :=
        { method := "GET"
          path := "/example/.."
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    { name := "normalize-path/get-relative-relative"
      request :=
        { method := "GET"
          path := "/example1/example2/../.."
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    { name := "normalize-path/get-slash"
      request :=
        { method := "GET"
          path := "//"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    { name := "normalize-path/get-slash-dot-slash"
      request :=
        { method := "GET"
          path := "/./"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    { name := "normalize-path/get-slash-pointless-dot"
      request :=
        { method := "GET"
          path := "/./example"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/example\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n214d50c111a8edc4819da6a636336472c916b5240f51e9a51b5c3305180cf702"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=ef75d96142cf21edca26f06005da7988e4f8dc83a165a80865db7089db637ec5" },
    { name := "normalize-path/get-slashes"
      request :=
        { method := "GET"
          path := "//example//"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/example/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\ncb96b4ac96d501f7c5c15bc6d67b3035061cfced4af6585ad927f7e6c985c015"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=9a624bd73a37c9a373b5312afbebe7a714a789de108f0bdfe846570885f57e84" },
    { name := "normalize-path/get-space"
      request :=
        { method := "GET"
          path := "/example space/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "GET\n/example%20space/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n63ee75631ed7234ae61b5f736dfc7754cdccfedbff4b5128a915706ee9390d86"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741" },
    { name := "post-header-key-case"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b" },
    { name := "post-header-key-sort"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("My-Header1", "value1")]
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n9368318c2967cf6de74404b30c65a91e8f6253e0a8659d6d5319f1a812f87d65"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c" },
    { name := "post-header-value-case"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("My-Header1", "VALUE1")]
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\nhost:example.amazonaws.com\nmy-header1:VALUE1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nd51ced243e649e3de6ef63afbbdcbca03131a21a7103a1583706a64618606a93"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=cdbc9802e29d2942e5e10b5bccfdd67c5f22c7c4e8ae67b53629efa58b974b7d" },
    { name := "post-sts-token/post-sts-header-after"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b" },
    { name := "post-sts-token/post-sts-header-before"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := some "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
      canonical := "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\nx-amz-security-token:AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==\n\nhost;x-amz-date;x-amz-security-token\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nc237e1b440d4c63c32ca95b5b99481081cb7b13c7e40434868e71567c1a882f6"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead" },
    { name := "post-vanilla"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b" },
    { name := "post-vanilla-empty-query-value"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := [("Param1", "value1")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\nParam1=value1\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n9d659678c1756bb3113e2ce898845a0a79dbbc57b740555917687f1b3340fbbd"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11" },
    { name := "post-vanilla-query"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := [("Param1", "value1")]
          headers := []
          body := "".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\nParam1=value1\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n9d659678c1756bb3113e2ce898845a0a79dbbc57b740555917687f1b3340fbbd"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11" },
    { name := "post-x-www-form-urlencoded"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("Content-Type", "application/x-www-form-urlencoded")]
          body := "Param1=value1".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n42a5e5bb34198acb3e84da4f085bb7927f2bc277ca766e6d19c73c2154021281"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a" },
    { name := "post-x-www-form-urlencoded-parameters"
      request :=
        { method := "POST"
          path := "/"
          host := "example.amazonaws.com"
          query := []
          headers := [("Content-Type", "application/x-www-form-urlencoded; charset=utf8")]
          body := "Param1=value1".toUTF8 }
      sessionToken := none
      canonical := "POST\n/\n\ncontent-type:application/x-www-form-urlencoded; charset=utf8\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e"
      stringToSign := "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n2e1cf7ed91881a30569e46552437e4156c823447bf1781b921b5d486c568dd1c"
      authorization := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=1a72ec8f64bd914b0e42e42607c7fbce7fb2c7465f63e3092b3b0d39fa77a6fe" }
  ]

def checks : List (String × Bool) :=
  cases.flatMap fun c =>
    let signed := sign (credentialsFor c.sessionToken) scope instant c.request
    [ (s!"{c.name}: canonical request", signed.canonicalRequest == c.canonical),
      (s!"{c.name}: string to sign", signed.stringToSign == c.stringToSign),
      (s!"{c.name}: authorization header",
        signed.headers.any fun h => h.1 == "Authorization" && h.2 == c.authorization) ]

end Tests.Suite
