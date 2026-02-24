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

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcutil" // تم تعديل المسار هنا ليتناسب مع النسخة المستقرة
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

var (
	totalChecked uint64
	startTime    = time.Now()
	token        = "5921618897:AAGu6bp5gFtatio22y-XdWUSwAd0Lk6b1HY"
	chatID       = "227172927"
	fileURL      = "https://drive.google.com/uc?export=download&id=1WGGjb1WQ6kkeA1x_2eQo-uecYg8RXLDb"
	workerName   = "GitHub-Matrix-Worker"
)

func pubKeyToLegacy(pubKey []byte) string {
	h256 := sha256.Sum256(pubKey)
	hasher := ripemd160.New()
	hasher.Write(h256[:])
	return base58.CheckEncode(hasher.Sum(nil), 0x00)
}

func pubKeyToSegwit(pubKey []byte) (string, string) {
	witnessAddr, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey), &chaincfg.MainNetParams)
	hash160 := btcutil.Hash160(pubKey)
	scriptSig := append([]byte{0x00, 0x14}, hash160...)
	p2shAddr, _ := btcutil.NewAddressScriptHash(scriptSig, &chaincfg.MainNetParams)
	return witnessAddr.EncodeAddress(), p2shAddr.EncodeAddress()
}

func main() {
	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	fmt.Println("🚀 جاري سحب الأهداف...")
	resp, err := http.Get(fileURL)
	if err != nil { return }
	
	targets := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		targets[strings.TrimSpace(scanner.Text())] = true
	}
	resp.Body.Close()
	fmt.Printf("✅ انطلقنا! الأهداف: %d\n", len(targets))

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
				pubComp := priv.PubKey().SerializeCompressed()
				pubUnComp := priv.PubKey().SerializeUncompressed()

				a1 := pubKeyToLegacy(pubComp)
				a2 := pubKeyToLegacy(pubUnComp)
				a3, a4 := pubKeyToSegwit(pubComp)

				if targets[a1] || targets[a2] || targets[a3] || targets[a4] {
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
	report := fmt.Sprintf("🤖 *المصدر: [%s]*\n⏱ دقيقة: %.1f\n🚀 سرعة: %.0f\n💎 إجمالي: %d", 
		workerName, elapsed/60, speed, atomic.LoadUint64(&totalChecked))
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 [JACKPOT] FOUND!\nSource: %s\nAddress: %s\nKey: %x", workerName, addr, priv.Serialize())
	sendTelegram(msg)
}
