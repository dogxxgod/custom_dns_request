package main
import (
    "encoding/binary"
    "github.com/miekg/dns"
    "golang.org/x/net/ipv4"
    "log"
	"net"
	flag "github.com/spf13/pflag"
	"math/rand"
	"fmt"
    "time"
    "strings"
	"io/ioutil"
)


func send_dns_request(dns_server string, sip string,domain string ,qtype uint16){
    buff := NewMsg(domain,qtype)
    // dst := net.IPv4(10,91,3,55)
	// src := net.IPv4(100, 108, 199, 100)

	dst := net.ParseIP(dns_server) 
	src := net.ParseIP(sip) 
    iph := &ipv4.Header{
        Version:  ipv4.Version,
        Len:      ipv4.HeaderLen,
        TOS:      0x00,
        TotalLen: ipv4.HeaderLen + len(buff),
        TTL:      64,
        Flags:    ipv4.DontFragment,
        FragOff:  0,
        Protocol: 17,
        Checksum: 0,
        Src:      src,
        Dst:      dst,
    }
    h, err := iph.Marshal()
    if err != nil {
        log.Fatal(err)
    }

    iph.Checksum = int(checkSum(h))
    //填充udp首部
    //udp伪首部
    pudph := PseudoHeader{
        SrcIP:  src,
        DstIP:  dst,
        Zero:   0,
        Proto:  17,
        Length: uint16(len(buff)) + 8,
	}
	sport := uint16(10000 + rand.Intn(60000-10000))

    udph := UDPHeader{
        SPort:    sport,
        DPort:    53,
        Length:   uint16(len(buff)) + 8,
        CheckSum: 0,
    }

    pudph.UDPHeader = udph
    udphb := pudph.Bytes()
    check := checkSum(append(udphb, buff...))

    binary.BigEndian.PutUint16(udphb[18:], check)
    laddr, err := net.ResolveIPAddr("ip4", "0.0.0.0")
    if err != nil {
        log.Println(err)
        return
	}
	// fmt.Println("sport:",laddr.SrcPort)
    c, err := net.ListenIP("ip4:udp", laddr)
    if err != nil {
        log.Println(err)
        return
    }
    conn, err := ipv4.NewRawConn(c)
    if err != nil {
        log.Println(err)
        return
    }
    err = conn.WriteTo(iph, append(udphb[12:20], buff...), nil)
    if err != nil {


        log.Println(err)

	}
	conn.Close()

}


func read_file(filename string) []string {
	var rt []string
	if contents,err := ioutil.ReadFile(filename);err == nil {
		//因为contents是[]byte类型，直接转换成string类型后会多一行空格,需要使用strings.Replace替换换行符
		for _, line := range strings.Split(string(contents), "\n") {
            line = strings.TrimSpace(line)
            if len(line) > 0{
                rt = append(rt,line)
            }
			
		}
	}
	return rt		
}






func checkSum(msg []byte) uint16 {


    var (


        sum    uint32


        length int = len(msg)


        index  int


    )


    for length > 1 {


        sum += uint32(msg[index])<<8 + uint32(msg[index+1])


        index += 2


        length -= 2


    }


    if length > 0 {


        sum += uint32(msg[index])<<8


    }


    sum += (sum >> 16)


    return uint16(^sum)


}




func NewMsg(domain string, qtype uint16) []byte {


    msg := new(dns.Msg)


    msg.Id = dns.Id()


    msg.RecursionDesired = true


    msg.Question = make([]dns.Question, 1)


    msg.Question[0] = dns.Question{


        Qtype:  qtype,


        Qclass: dns.ClassINET,


        Name:   domain + ".",


    }


    b, err := msg.Pack()


    if err != nil {


        log.Fatal(err)


    }


    return b


}




type PseudoHeader struct {


    SrcIP  net.IP


    DstIP  net.IP


    Zero   byte


    Proto  byte


    Length uint16


    UDPHeader


}




func (p PseudoHeader) Bytes() []byte {


    var b = make([]byte, 20)


    b[0], b[1], b[2], b[3] = p.SrcIP[12], p.SrcIP[13], p.SrcIP[14], p.SrcIP[15]


    b[4], b[5], b[6], b[7] = p.DstIP[12], p.DstIP[13], p.DstIP[14], p.DstIP[15]


    b[8] = p.Zero


    b[9] = p.Proto


    binary.BigEndian.PutUint16(b[10:12], p.Length)


    binary.BigEndian.PutUint16(b[12:], p.SPort)


    binary.BigEndian.PutUint16(b[14:], p.DPort)


    binary.BigEndian.PutUint16(b[16:], p.Length)


    binary.BigEndian.PutUint16(b[18:], p.CheckSum)


    return b


}




type UDPHeader struct {


    SPort    uint16


    DPort    uint16


    Length   uint16


    CheckSum uint16


}




func (p UDPHeader) Bytes() []byte {


    var b = make([]byte, 8)


    binary.BigEndian.PutUint16(b[:2], p.SPort)


    binary.BigEndian.PutUint16(b[2:4], p.DPort)


    binary.BigEndian.PutUint16(b[4:6], p.Length)


    binary.BigEndian.PutUint16(b[6:8], p.CheckSum)


    return b


}

func main(){
	server := flag.String("server", "", "dns server ip")
	speed := flag.Int("speed", 1, "request speed")

	var domain string
	flag.StringVar(&domain, "domain", "not set", "domain name")

	var sip string
    flag.StringVar(&sip, "sip", "127.0.0.1", "domains filepath")
    
    var qtype uint16
    flag.Uint16Var(&qtype, "qtype", 1, "A:1, CNAME:5, NS:2, SOA:6")
    
    var debug string
    flag.StringVar(&debug, "debug", "n", "is debug mode: y or n ")
    

    var domain_filepath string
    flag.StringVar(&domain_filepath, "domain_filepath", "not set", "domain filepath")

    var ip_filepath string
    flag.StringVar(&ip_filepath, "ip_filepath", "not set", "ip  filepath")
    
    flag.Parse()
    total := 0
	last_time := time.Now()
    if (domain_filepath != "not set") &&  (ip_filepath != "not_set") {
        domains_lst := read_file(domain_filepath)
        ip_lst := read_file(ip_filepath)
        for {
            for _,sip := range ip_lst{
                for _,domain := range domains_lst {
                    // if debug == "y"{
                    //     fmt.Println("request:",*server,sip,domain,qtype)
                    // }
                    send_dns_request(*server,sip,domain,qtype)
                    total += 1
                    if total % *speed == 0{
                        now := time.Now()
                        use_time := now.Sub(last_time).Nanoseconds()/1000000 
                        if debug == "y"{
                            fmt.Println(now.Format("2006-01-02 15:04:05")," count:",total," use-time:",use_time," ms")
                        }
                        sleep_time := 1000 - use_time
                        if sleep_time > 0{
                            // fmt.Println("sleep:",sleep_time)
                            time.Sleep(time.Duration(sleep_time*1000000))
                        }else{
                            fmt.Println("speed too large !")
                        }
                        last_time = time.Now()
                        
                    }
                }
            }
        }

    }else{
        send_dns_request(*server,sip,domain,qtype)
    }

}

