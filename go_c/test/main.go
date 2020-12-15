package main
import ( "fmt"
 "os"
 "io/ioutil"
  "time"
  "strconv"
  _  "../sub"
 )
func init() {
   fmt.Println("init in main.go ")
}
func Read0()  (int){
            f, err := ioutil.ReadFile("pid.txt")
            if err != nil {
                fmt.Println("read fail", err)
        }
            pid,_ := strconv.Atoi(string(f))

            fmt.Printf("pid %d  \n", pid)
            return pid
}

func main(){
        time.Sleep(2)
        pid :=Read0()
        fmt.Printf("Hello c, welcome to go! pid %d and child %d", os.Getpid(), pid)
        proc, err := os.FindProcess(pid)
        if err != nil {
                                        panic(err.Error())
        }
        state, err := proc.Wait()
        if err != nil {
        panic(err.Error())
        }
        println("string:", state.String())
        println("pid:", state.Pid())
        println("Parent dies now.")
}
