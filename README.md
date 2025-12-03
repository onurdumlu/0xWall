<div align="center">

# 🛡️ AI-Powered Hybrid Firewall (Edge-Cloud)
### Raspberry Pi & LLM Entegrasyonlu Akıllı Güvenlik Duvarı

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Raspberry Pi](https://img.shields.io/badge/Hardware-Raspberry%20Pi%204-C51A4A?style=for-the-badge&logo=raspberry-pi&logoColor=white)](https://www.raspberrypi.org/)
[![Google Colab](https://img.shields.io/badge/Cloud-Google%20Colab-F9AB00?style=for-the-badge&logo=google-colab&logoColor=white)](https://colab.research.google.com/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey?style=for-the-badge)](LICENSE.md)

<br/>

**Siber tehditleri LLaMa-3 tabanlı yapay zeka ile analiz eden, Raspberry Pi üzerinde çalışan ve cerrahi engelleme yapan yeni nesil UTM (Unified Threat Management) çözümü.**

[Özellikler](#-özellikler) • [Mimari](#-sistem-mimarisi) 

</div>

---

## 🚀 Proje Hakkında

Geleneksel güvenlik duvarları statik kurallarla çalışır. Bu proje ise ağ trafiğini (`.pcap`) dinler, **Uç Bilişim (Edge Computing)** ve **Bulut Bilişim (Cloud Computing)** mimarisini birleştirerek trafiği analiz eder.

**Raspberry Pi (İstemci)** ağ paketlerini toplar, **Google Colab (Sunucu)** üzerindeki **LLaMa-PcapLog** modeline gönderir. Yapay zeka, trafiğin saldırı olup olmadığına karar verir ve Pi üzerindeki **iptables** kurallarını dinamik olarak günceller.

## 🌟 Özellikler

* **🧠 Yapay Zeka Destekli Analiz:** TShark ve Llama-3 modeli ile semantik trafik analizi.
* **⚡ Gerçek Zamanlı Koruma:** 15 saniyelik periyotlarla tehdit avcılığı.
* **🛡️ Cerrahi Engelleme:** Sadece saldırgan IP adresini hedef alan nokta atışı savunma.
* **📊 Gelişmiş Web Paneli (Dashboard):** * Canlı saldırı izleme ve loglama.
    * CPU, RAM ve Sıcaklık takibi.
    * IP Beyaz Liste (Whitelist) yönetimi.
* **🌐 Web Filtreleme (Domain Blocking):** `zararlisite.com` gibi siteleri IP çözümlemesiyle engelleme.
* **💻 Web Terminal & Lockdown:** Panel üzerinden komut satırı erişimi ve tek tuşla SSH kapatma (Kiosk Modu).
* **🔐 Rol Tabanlı Yetkilendirme (RBAC):** Admin ve kısıtlı kullanıcı rolleri.

---

## 🏗 Sistem Mimarisi

Aşağıdaki diyagram, sistemin veri akışını ve hibrit yapısını göstermektedir:

```mermaid
graph LR
    subgraph "Uç Birim (Raspberry Pi)"
        A[Scapy Sniffer] -->|1. Pcap Oluştur| B[Client Script]
        B -->|4. Iptables Engelleme| C[Firewall Kuralları]
        D[Streamlit Dashboard] -.->|Yönetim| C
    end
    
    subgraph "İletişim Kanalı"
        B -->|2. POST Request| E[Ngrok Tünel]
    end
    
    subgraph "Bulut (Google Colab)"
        E -->|3. Veri İletimi| F[Flask API]
        F -->|TShark Analizi| G[LLaMa-PcapLog Modeli]
        G -->|JSON Yanıt| F
        F -->|Karar: BLOCKED| B
    end
