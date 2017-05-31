package radius

import(
//"fmt"
)
func init() {
  //RFC 2869 (not full, see https://www.ietf.org/rfc/rfc2869.txt)
  Builtin.MustRegister("Acct-Input-Gigawords", 52, AttributeInteger)
  Builtin.MustRegister("Acct-Output-Gigawords", 53, AttributeInteger)
  Builtin.MustRegister("NAS-Port-ID", 87, AttributeString)
}
