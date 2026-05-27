/*
  ESP32 MQTT Sensor Publisher for Secure QoS-Aware Edge IoT Optimizer
  Libraries required in Arduino IDE:
  - WiFi.h
  - PubSubClient by Nick O'Leary

  Note: Arduino C++ does not include HMAC-SHA256 in this minimal sketch.
  For the full security demo, either:
  1) add an HMAC library and generate the same signature as Python security.py, or
  2) publish unsigned demo packets and sign them at a trusted gateway.
*/

#include <WiFi.h>
#include <PubSubClient.h>

const char* WIFI_SSID = "YOUR_WIFI";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* MQTT_HOST = "192.168.1.10";
const int MQTT_PORT = 1883;
const char* TOPIC = "iot/packets";

WiFiClient espClient;
PubSubClient client(espClient);

String deviceId = "esp32-a";
unsigned long counter = 0;

void connectWiFi() {
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
}

void connectMQTT() {
  while (!client.connected()) {
    String clientId = deviceId + "-client";
    if (!client.connect(clientId.c_str())) {
      delay(1000);
    }
  }
}

String makePacketJson() {
  counter++;
  float value = 20.0 + random(0, 1000) / 100.0;
  int isCritical = random(0, 10) > 7;
  String sensorType = isCritical ? "fire" : "temperature";
  int priority = isCritical ? 10 : 5;
  int sensitivity = isCritical ? 10 : 4;
  int deadline = isCritical ? 300 : 1500;

  String json = "{";
  json += "\"packet_id\":\"" + deviceId + "-" + String(counter) + "\",";
  json += "\"source\":\"" + deviceId + "\",";
  json += "\"destination\":\"cloud\",";
  json += "\"size_bytes\":512,";
  json += "\"sensor_type\":\"" + sensorType + "\",";
  json += "\"priority\":" + String(priority) + ",";
  json += "\"deadline_ms\":" + String(deadline) + ",";
  json += "\"sensitivity\":" + String(sensitivity) + ",";
  json += "\"payload\":\"{\\\"value\\\":" + String(value) + "}\",";
  json += "\"signature\":null";
  json += "}";
  return json;
}

void setup() {
  randomSeed(analogRead(0));
  connectWiFi();
  client.setServer(MQTT_HOST, MQTT_PORT);
}

void loop() {
  if (!client.connected()) {
    connectMQTT();
  }
  client.loop();

  String payload = makePacketJson();
  client.publish(TOPIC, payload.c_str(), false);
  delay(2000);
}
