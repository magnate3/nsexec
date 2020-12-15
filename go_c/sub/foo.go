package   sub 
/*
extern void nsexec();
void __attribute__((constructor)) init(void) {
		nsexec();
	}
*/
import "C"
var AlwaysFalse bool

//cgo CFLAGS: -Wall
// AlwaysFalse is here to stay false
// (and be exported so the compiler doesn't optimize out its reference)
func init() {
	if AlwaysFalse {
	 C.init()
 }
}

