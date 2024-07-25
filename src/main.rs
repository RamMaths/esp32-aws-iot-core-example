use std::time::Duration;

use crossbeam_channel::bounded;
use esp_idf_hal::cpu::Core;
use esp_idf_hal::sys::EspError;
use esp_idf_hal::task::watchdog::{TWDTConfig, TWDTDriver};
use esp_idf_hal::{
    gpio::{OutputPin, PinDriver},
    peripherals::Peripherals,
};
use esp_idf_svc::mqtt::client::QoS;
use log::*;
use ultrasonic::startup::App;

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    // This sets the wifi and creates an http client
    let app = App::spawn()?;
    let peripherals = Peripherals::take().unwrap();

    let mut led = PinDriver::output(peripherals.pins.gpio5.downgrade_output())?;

    let (tx_mqtt, rx_mqtt) = bounded::<String>(1);

    let _ultrasonic_thread = std::thread::Builder::new()
        .stack_size(2000)
        .spawn(move || loop {
            match rx_mqtt.try_recv() {
                Ok(kind) => {}
                Err(_) => {}
            }
        })?;

    run_mqtt(app)?;
    Ok(())
}

fn run_mqtt(mut app: App) -> Result<(), EspError> {
    let pub_topic = &app.client.pub_topic;
    let sub_topic = &app.client.sub_topic;
    std::thread::scope(|s| {
        info!("About to start the MQTT client");

        // Need to immediately start pumping the connection for messages, or else subscribe() and publish() below will not work
        // Note that when using the alternative constructor - `EspMqttClient::new_cb` - you don't need to
        // spawn a new thread, as the messages will be pumped with a backpressure into the callback you provide.
        // Yet, you still need to efficiently process each message in the callback without blocking for too long.
        //
        // Note also that if you go to http://tools.emqx.io/ and then connect and send a message to topic
        // "esp-mqtt-demo", the client configured here should receive it.
        std::thread::Builder::new()
            .stack_size(6000)
            .spawn_scoped(s, move || {
                info!("MQTT Listening for messages");

                while let Ok(event) = app.client.mqtt_connection.next() {
                    info!("[Queue] Event: {}", event.payload());
                }

                info!("Connection closed");
            })
            .unwrap();

        loop {
            if let Err(e) = app.client.mqtt_client.subscribe(sub_topic, QoS::AtMostOnce) {
                error!("Failed to subscribe to topic \"{sub_topic}\": {e}, retrying...");

                // Re-try in 0.5s
                std::thread::sleep(Duration::from_millis(500));

                continue;
            }

            info!("Subscribed to topic \"{sub_topic}\"");

            // Just to give a chance of our connection to get even the first published message
            std::thread::sleep(Duration::from_millis(500));

            let payload = "Hello from esp-mqtt-demo!";

            loop {
                // app.client.mqtt_client.enqueue(
                //     pub_topic,
                //     QoS::AtMostOnce,
                //     false,
                //     payload.as_bytes(),
                // )?;

                // info!("Published \"{payload}\" to topic \"{pub_topic}\"");

                let sleep_secs = 2;
                //
                // info!("Now sleeping for {sleep_secs}s...");
                std::thread::sleep(Duration::from_secs(sleep_secs));
            }
        }
    })
}
