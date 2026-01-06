import requests
import random
from mcp.server.fastmcp import FastMCP

# 1. MCP Sunucu Tanımı
mcp = FastMCP("Velora Assistant MCP")

# 2. TOOL: Rastgele Motivasyon Sözü (Public API + Fallback)
@mcp.tool()
def get_motivation_quote() -> str:
    """
    İnternetten rastgele bir motivasyon sözü getirir.
    Hata durumunda Velora AI yedek sözlerini kullanır.
    """
    url = "https://zenquotes.io/api/random"
    
    # Yedek Sözler (İnternet yoksa devreye girer)
    fallback_quotes = [
        ("Büyük işler, küçük adımlarla başlar.", "Velora AI"),
        ("Kodlamak, geleceği inşa etmektir.", "Velora AI"),
        ("Hata yapmaktan korkma, düzeltmekten kork.", "Velora AI"),
        ("Bugün dünden daha iyi ol.", "Velora AI")
    ]
    
    try:
        # Request ile uzak adrese sorgu atıyoruz (3 saniye zaman aşımı)
        response = requests.get(url, timeout=3)
        
        if response.status_code == 200:
            data = response.json()[0]
            quote = data['q']
            author = data['a']
            return f"🌟 Günün Sözü: '{quote}' - {author}"
            
    except Exception as e:
        print(f"API Hatası (MCP): {e}")

    # Hata varsa veya internet yoksa yedeklerden seç
    quote, author = random.choice(fallback_quotes)
    return f"🌟 Günün Sözü: '{quote}' - {author}"

# 3. TOOL: Sistem Durumu (Local API Kullanımı)
@mcp.tool()
def check_system_health() -> str:
    """Velora sisteminin sağlık durumunu kontrol eder."""
    try:
        # Docker içindeki backend servisine istek atıyoruz
        resp = requests.get("http://velora-api:8000/metrics", timeout=2)
        if resp.status_code == 200:
            return "✅ Sistem çalışıyor ve metrikler toplanıyor."
        return "⚠️ Sistem yanıt vermiyor (Status code hatası)."
    except Exception as e:
        return f"❌ Bağlantı hatası: {str(e)}"

if __name__ == "__main__":
    mcp.run()