import asyncio
import time
import requests
import ollama
import os
import datetime

# Docker içindeki servis adresleri
API_URL = "http://velora-api:8000"
# Ollama artık ayrı bir servis ve 11434 portunda
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")

# Raporun kaydedileceği yer
REPORT_DIR = "/app/reports"

# Ollama İstemcisi
ai_client = ollama.Client(host=OLLAMA_HOST)
MODEL_NAME = 'gemma:2b'

def ensure_model_exists():
    """Modelin yüklü olduğundan emin ol, yoksa indir."""
    print(f"🤖 Model kontrol ediliyor: {MODEL_NAME}")
    try:
        # Mevcut modelleri listele
        models = ai_client.list()
        # Modelleri string listesine çevirip kontrol et
        model_names = [m['name'] for m in models.get('models', [])]
        
        # 'gemma:2b' ismini içeren bir model var mı?
        found = any(MODEL_NAME in name for name in model_names)
        
        if not found:
            print(f"⬇️ Model bulunamadı, indiriliyor: {MODEL_NAME} (Bu işlem biraz sürebilir...)")
            ai_client.pull(MODEL_NAME)
            print("✅ Model indirildi!")
        else:
            print("✅ Model zaten hazır.")
    except Exception as e:
        print(f"⚠️ Model kontrol hatası (Ollama henüz hazır olmayabilir): {e}")

def get_velora_metrics():
    """Velora API'den güncel istatistikleri çeker"""
    try:
        resp = requests.get(f"{API_URL}/metrics")
        data = resp.text
        metrics = {}
        for line in data.split('\n'):
            if line.startswith('velora_total_tasks'):
                metrics['tasks'] = line.split(' ')[1]
            elif line.startswith('velora_total_passwords'):
                metrics['passwords'] = line.split(' ')[1]
            elif line.startswith('velora_total_reminders'):
                metrics['reminders'] = line.split(' ')[1]
        return metrics
    except Exception as e:
        print(f"Metrik hatası: {e}")
        return {}

async def generate_daily_briefing():
    print(f"[{datetime.datetime.now()}] 🤖 Velora Asistanı rapor hazırlıyor...")
    
    metrics = get_velora_metrics()
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    
    prompt = f"""
    Sen Velora Kişisel Asistanısın. Kullanıcının bugünkü durumunu analiz et ve kısa bir özet rapor yaz.
    
    Veriler:
    - Bekleyen Görev Sayısı: {metrics.get('tasks', '0')}
    - Kayıtlı Şifre Sayısı: {metrics.get('passwords', '0')}
    
    Görevin:
    1. Kullanıcıyı motive et.
    2. Eğer görev sayısı 5'ten fazlaysa "Yoğun bir gün" uyarısı yap.
    3. Şifre sayısı 0 ise "Kasanı kullanmaya başla" tavsiyesi ver.
    4. Türkçe konuş.
    """
    
    try:
        ensure_model_exists() # Her denemede modeli kontrol et
        response = ai_client.chat(model=MODEL_NAME, messages=[{'role': 'user', 'content': prompt}])
        ai_content = response['message']['content']
        
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
            
        filename = f"{REPORT_DIR}/Gunluk_Ozet_{today}.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# 📅 Velora Günlük Özet: {today}\n\n")
            f.write(f"### 📊 Sistem İstatistikleri\n")
            f.write(f"- **Görevler:** {metrics.get('tasks', 'N/A')}\n")
            f.write(f"- **Şifreler:** {metrics.get('passwords', 'N/A')}\n\n")
            f.write(f"### 🤖 AI Asistan Notu\n")
            f.write(ai_content)
            
        print(f"✅ Rapor oluşturuldu: {filename}")
        
    except Exception as e:
        print(f"❌ AI Hatası: {e}")

if __name__ == "__main__":
    print("Sistem açılıyor, servislerin kendine gelmesi için 20sn bekleniyor...")
    time.sleep(20)
    
    # İlk açılışta modeli çekmeyi dene
    ensure_model_exists()
    
    while True:
        try:
            asyncio.run(generate_daily_briefing())
        except Exception as e:
            print(f"Genel Hata: {e}")
        
        print("💤 Asistan uyku moduna geçti (300sn)...")
        time.sleep(300)