/*
  FireGuard - Alarme incendie connectée (ESP32)
  Capteurs : DHT11 (GPIO4), MQ-2 (GPIO34), Flame (GPIO27)
  Sorties  : Buzzer actif (GPIO26), LED intégrée (GPIO2)
  Réseau   : Wi-Fi -> MQTT (TLS 1.2+) -> broker Mosquitto

  Bibliothèques (Gestionnaire de bibliothèques Arduino) :
    - PubSubClient (Nick O'Leary)
    - DHT sensor library (Adafruit) + Adafruit Unified Sensor
  Carte : "ESP32 Dev Module" (paquet esp32 by Espressif)
*/

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include "mbedtls/md.h"
#include "secrets.h"

// ---------- Options ----------
#define USE_TLS 1            // 0 = MQTT en clair (port 1883) pour les premiers tests uniquement

// ---------- Broches ----------
const int PIN_DHT    = 4;
const int PIN_GAS    = 34;   // ADC1 -> compatible Wi-Fi
const int PIN_FLAME  = 27;
const int PIN_BUZZER = 26;
const int PIN_LED    = 2;    // LED intégrée

// ---------- Seuils (à calibrer !) ----------
const float TEMP_THRESHOLD   = 50.0;   // °C
const int   GAS_THRESHOLD    = 1800;   // 0..4095 : regarde les valeurs au repos puis ajuste
const unsigned long MQ_WARMUP_MS = 120000; // le MQ-2 chauffe 2 min : pas d'alarme gaz avant
const bool  FLAME_ACTIVE_LOW = true;   // la plupart des modules mettent DO à LOW si flamme

// ---------- MQTT ----------
const char* DEVICE_ID    = "device1";
const char* TOPIC_DATA   = "fireguard/device1/data";
const char* TOPIC_CMD    = "fireguard/device1/cmd";
const char* TOPIC_STATUS = "fireguard/device1/status";

// ---------- Périodes ----------
const unsigned long SENSOR_PERIOD_MS  = 500;    // lecture locale (alarme réactive)
const unsigned long PUBLISH_PERIOD_MS = 2000;   // envoi MQTT + lecture DHT11

#if USE_TLS
WiFiClientSecure netClient;
#else
WiFiClient netClient;
#endif
PubSubClient mqtt(netClient);
DHT dht(PIN_DHT, DHT11);

// ---------- État ----------
enum BuzzerMode { MODE_AUTO, MODE_FORCE_ON, MODE_MUTE };
BuzzerMode mode = MODE_AUTO;

float temperature = NAN, humidity = NAN;
int   gasValue = 0;
bool  flameDetected = false, gasHigh = false, tempHigh = false;
bool  alarmActive = false, buzzerOn = false;

unsigned long lastSensor = 0, lastPublish = 0, lastMqttTry = 0;

// ---------- HMAC-SHA256 (intégrité + authenticité du message) ----------
String hmacSha256(const String& msg) {
  uint8_t out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)HMAC_KEY, strlen(HMAC_KEY));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", out[i]);
  return String(hex);
}

// ---------- Wi-Fi + heure (nécessaire pour valider le certificat TLS) ----------
void connectWifi() {
  Serial.printf("Wi-Fi: connexion à %s", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\nWi-Fi OK, IP = %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\nWi-Fi: échec (nouvel essai plus tard)");
  }
}

void syncTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("NTP: synchronisation");
  unsigned long t0 = millis();
  while (time(nullptr) < 1700000000 && millis() - t0 < 15000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println(time(nullptr) >= 1700000000 ? " OK" : " échec");
}

// ---------- Réception des commandes (depuis le dashboard via le backend) ----------
void onMessage(char* topic, byte* payload, unsigned int len) {
  String msg;
  for (unsigned int i = 0; i < len; i++) msg += (char)payload[i];
  msg.trim();
  msg.toUpperCase();
  Serial.printf("MQTT cmd reçue: %s\n", msg.c_str());

  if (msg == "ON")        mode = MODE_FORCE_ON;   // buzzer forcé
  else if (msg == "OFF")  mode = MODE_MUTE;       // buzzer coupé (silence)
  else if (msg == "AUTO") mode = MODE_AUTO;       // retour au mode automatique
}

// ---------- Connexion MQTT ----------
bool connectMqtt() {
  String clientId = String("fireguard-") + DEVICE_ID;
  // Last Will : si l'ESP32 disparaît, le broker publie "offline"
  if (mqtt.connect(clientId.c_str(), MQTT_USER, MQTT_PASS,
                   TOPIC_STATUS, 1, true, "offline")) {
    Serial.println("MQTT: connecté");
    mqtt.publish(TOPIC_STATUS, "online", true);
    mqtt.subscribe(TOPIC_CMD, 1);
    return true;
  }
  Serial.printf("MQTT: échec, rc=%d\n", mqtt.state());
  return false;
}

// ---------- Lecture des capteurs + logique d'alarme ----------
void readFastSensors() {
  long sum = 0;
  for (int i = 0; i < 8; i++) sum += analogRead(PIN_GAS);
  gasValue = sum / 8;

  int f = digitalRead(PIN_FLAME);
  flameDetected = FLAME_ACTIVE_LOW ? (f == LOW) : (f == HIGH);

  bool warmedUp = millis() > MQ_WARMUP_MS;
  gasHigh  = warmedUp && (gasValue > GAS_THRESHOLD);
  tempHigh = !isnan(temperature) && (temperature > TEMP_THRESHOLD);

  alarmActive = flameDetected || gasHigh || tempHigh;

  buzzerOn = (mode == MODE_FORCE_ON) || (mode == MODE_AUTO && alarmActive);
  digitalWrite(PIN_BUZZER, buzzerOn ? HIGH : LOW);
  digitalWrite(PIN_LED, alarmActive ? HIGH : LOW);
}

void readDht() {
  float h = dht.readHumidity();
  float t = dht.readTemperature();
  if (!isnan(h)) humidity = h;
  if (!isnan(t)) temperature = t;
}

// ---------- Publication : JSON|signature ----------
void publishData() {
  if (!mqtt.connected()) return;

  String t = isnan(temperature) ? "null" : String(temperature, 1);
  String h = isnan(humidity)    ? "null" : String(humidity, 1);

  char body[220];
  snprintf(body, sizeof(body),
           "{\"device\":\"%s\",\"ts\":%lu,\"temp\":%s,\"hum\":%s,"
           "\"gas\":%d,\"flame\":%d,\"alarm\":%d,\"buzzer\":%d}",
           DEVICE_ID, (unsigned long)time(nullptr), t.c_str(), h.c_str(),
           gasValue, flameDetected ? 1 : 0, alarmActive ? 1 : 0, buzzerOn ? 1 : 0);

  // Format final : <json>|<hmac hex>   (le backend sépare au dernier '|' et vérifie)
  String payload = String(body) + "|" + hmacSha256(String(body));

  bool ok = mqtt.publish(TOPIC_DATA, payload.c_str());
  Serial.printf("[%s] T=%s H=%s gaz=%d flamme=%d alarme=%d buzzer=%d\n",
                ok ? "OK" : "ERR", t.c_str(), h.c_str(), gasValue,
                flameDetected, alarmActive, buzzerOn);
}

// ---------- Arduino ----------
void setup() {
  Serial.begin(115200);
  pinMode(PIN_FLAME, INPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_LED, OUTPUT);
  digitalWrite(PIN_BUZZER, LOW);
  analogReadResolution(12);
  dht.begin();

  connectWifi();
  syncTime();

#if USE_TLS
  netClient.setCACert(CA_CERT);   // vérifie le certificat du broker
#endif
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
  mqtt.setBufferSize(512);        // payload JSON + signature > 256 octets par défaut
}

void loop() {
  unsigned long now = millis();

  // Wi-Fi
  if (WiFi.status() != WL_CONNECTED) {
    if (now - lastMqttTry > 5000) {
      lastMqttTry = now;
      connectWifi();
    }
  }

  // MQTT (reconnexion toutes les 5 s, sans bloquer l'alarme locale)
  if (WiFi.status() == WL_CONNECTED) {
    if (!mqtt.connected()) {
      if (now - lastMqttTry > 5000) {
        lastMqttTry = now;
        connectMqtt();
      }
    } else {
      mqtt.loop();
    }
  }

  // Alarme locale : fonctionne même sans Wi-Fi
  if (now - lastSensor >= SENSOR_PERIOD_MS) {
    lastSensor = now;
    bool wasAlarm = alarmActive;
    readFastSensors();
    if (alarmActive != wasAlarm) publishData();   // envoi immédiat si l'état change
  }

  // Envoi périodique
  if (now - lastPublish >= PUBLISH_PERIOD_MS) {
    lastPublish = now;
    readDht();
    publishData();
  }
}
