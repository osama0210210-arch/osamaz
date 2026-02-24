package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

var (
	totalChecked uint64
	startTime    = time.Now()
	token        = "5921618897:AAGu6bp5gFtatio22y-XdWUSwAd0Lk6b1HY"
	chatID       = "227172927"
	fileURL      = "https://www.dropbox.com/scl/fi/kpagj5u15zjeo0q5kg31t/wallets.txt?rlkey=0yc47js2rv5hvb2plcf9nqcgp&st=2xrliohq&dl=1"
	workerName   = "GitHub-Turbo-Reader"
)

func hash160(data []byte) []byte {
	h256 := sha256.Sum256(data)
	hasher := ripemd160.New()
	hasher.Write(h256[:])
	return hasher.Sum(nil)
}

func encodeAddress(pubKey []byte) string {
	return base58.CheckEncode(hash160(pubKey), 0x00)
}

func main() {
	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	sendTelegram("⚙️ جاري بدء سحب ملف الـ 33 مليون عنوان من Dropbox...")

	resp, err := http.Get(fileURL)
	if err != nil {
		sendTelegram("❌ خطأ في الاتصال")
		return
	}
	defer resp.Body.Close()

	targets := make(map[string]bool)
	// نظام قراءة متقدم للملفات العملاقة
	reader := bufio.NewReaderSize(resp.Body, 1024*1024) // 1MB Buffer
	
	for {
		line, err := reader.ReadString('\n')
		addr := strings.TrimSpace(line)
		if addr != "" {
			targets[addr] = true
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("⚠️ خطأ أثناء القراءة: %v\n", err)
			break
		}
	}

	count := len(targets)
	sendTelegram(fmt.Sprintf("✅ اكتمل التحميل!\nالعدد: %d عنوان\nالأنوية: %d\nبدأ الجلد... 🔥", count, cores))

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < cores*20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				addr := encodeAddress(priv.PubKey().SerializeCompressed())

				if targets[addr] {
					sendFound(addr, priv)
				}
				atomic.AddUint64(&totalChecked, 1)
			}
		}()
	}
	wg.Wait()
}

func sendReport() {
	elapsed := time.Since(startTime).Seconds()
	total := atomic.LoadUint64(&totalChecked)
	speed := float64(total) / elapsed
	
	priv, _ := btcec.NewPrivateKey()
	addr := encodeAddress(priv.PubKey().SerializeCompressed())

	report := fmt.Sprintf("📊 *تقرير الأداء*\n🚀 السرعة: %.0f/ث\n💎 الإجمالي: %d\n⏱ الدقائق: %.1f\n🔑 عينة: `%x` \n🏠 عنوان: `%s` ", 
		speed, total, elapsed/60, priv.Serialize(), addr)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 *[JACKPOT FOUND]*\nAddr: `%s` \nKey: `%x` ", addr, priv.Serialize())
	sendTelegram(msg)
}
