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
	// بياناتك الخاصة
	token      = "5921618897:AAGu6bp5gFtatio22y-XdWUSwAd0Lk6b1HY"
	chatID     = "227172927"
	// الرابط المباشر مع تخطي حماية جوجل للملفات الكبيرة
	fileURL    = "https://docs.google.com/uc?export=download&confirm=t&id=1WGGjb1WQ6kkeA1x_2eQo-uecYg8RXLDb"
	workerName = "GitHub-Matrix-Worker"
)

// دالة تحويل المفتاح العام لعنوان 1...
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

	// 1. إرسال رسالة فورية عند بدء التشغيل
	sendTelegram(fmt.Sprintf("✅ *بدأ التشغيل الآن!*\nالمصدر: [%s]\nالأنوية: %d\nجاري تحميل الأهداف...", workerName, cores))

	fmt.Println("🚀 جاري تحميل الأهداف...")
	resp, err := http.Get(fileURL)
	if err != nil {
		sendTelegram("❌ خطأ في تحميل ملف الأهداف من جوجل درايف")
		return
	}
	defer resp.Body.Close()

	targets := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	// لزيادة سعة القراءة للملفات الضخمة
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())
		if addr != "" {
			targets[addr] = true
		}
	}
	
	count := len(targets)
	fmt.Printf("✅ تم شحن %d هدف. انطلقنا!\n", count)
	sendTelegram(fmt.Sprintf("📥 *تم التحميل!*\nعدد الأهداف: %d\nالمحرقة بدأت الآن... 🔥", count))

	// 2. مؤقت التقارير الدوري (كل 5 دقائق)
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	// توزيع المهام على الأنوية
	for i := 0; i < cores*16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				
				// توليد النوعين الأساسيين لعنوان 1
				pubComp := priv.PubKey().SerializeCompressed()
				pubUncomp := priv.PubKey().SerializeUncompressed()
				
				a1 := encodeAddress(pubComp)
				a2 := encodeAddress(pubUncomp)

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
	total := atomic.LoadUint64(&totalChecked)
	speed := float64(total) / elapsed
	
	// توليد عينة عشوائية للتقرير
	priv, _ := btcec.NewPrivateKey()
	h := fmt.Sprintf("%x", priv.Serialize())
	a1 := encodeAddress(priv.PubKey().SerializeCompressed())
	a2 := encodeAddress(priv.PubKey().SerializeUncompressed())

	report := fmt.Sprintf("📊 *تقرير الخمس دقائق*\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🤖 المصدر: [%s]\n"+
		"🚀 السرعة: %.0f فحص/ث\n"+
		"💎 الإجمالي: %d\n"+
		"⏱ المدة: %.1f دقيقة\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🔑 عينة هيكس:\n`%s` \n"+
		"🏠 عينات عناوين:\n1️⃣ `%s` \n2️⃣ `%s` ", 
		workerName, speed, total, elapsed/60, h, a1, a2)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 *[JACKPOT] FOUND!*\n\nالمصدر: %s\nالعنوان: `%s` \nالمفتاح: `%x` ", 
		workerName, addr, priv.Serialize())
	sendTelegram(msg)
}
