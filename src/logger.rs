use chrono::Local;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::runtime::{ConfigBuilder, LoggerBuilder};
use log4rs::config::{Appender, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use std::mem;

/// Configures a file logger by modifying the provided logger builders and configuration.
///
/// # Arguments
/// * `builders` - A mutable slice of `LoggerBuilder` instances to be configured.
/// * `config` - A mutable reference to a `ConfigBuilder` to be updated with the file appender.
///
/// # Returns
/// An `anyhow::Result` indicating the success or failure of the operation.
fn file_logger(builders: &mut [LoggerBuilder], config: &mut ConfigBuilder) -> anyhow::Result<()> {
    builders
        .iter_mut()
        .for_each(|builder| *builder = mem::take(builder).appender("file"));

    let now = Local::now();
    let file = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} {h({l})} [{h({t})}] {m}{n}",
        )))
        .build(format!("logs/{}.log", now.format("%Y-%m-%d_%H:%M:%S")))?;

    *config = mem::take(config).appender(Appender::builder().build("file", Box::new(file)));
    Ok(())
}

/// Creates and initializes the logger configuration.
///
/// # Arguments
/// * `verbose` - A boolean indicating whether verbose logging should be enabled.
/// * `log_to_file` - A boolean indicating whether logs should be written to a file.
///
/// # Returns
/// An `anyhow::Result` indicating the success or failure of the operation.
pub(super) fn create_logger(verbose: bool, log_to_file: bool) -> anyhow::Result<()> {
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} {h({l})} [{h({t})}] {m}{n}",
        )))
        .build();

    let tls_logger_level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let fluxgate_logger = Logger::builder().appender("console");

    let tls_logger = Logger::builder().appender("console");

    let mut config = Config::builder();

    let mut loggers = [fluxgate_logger, tls_logger];

    if log_to_file {
        file_logger(&mut loggers, &mut config)?;
    }

    let fluxgate_logger = mem::take(&mut loggers[0]).build("fluxgate", LevelFilter::Debug);
    let tls_logger = mem::take(&mut loggers[1]).build("tls", tls_logger_level);

    let config = config
        .appender(Appender::builder().build("console", Box::new(console)))
        .loggers([fluxgate_logger, tls_logger])
        .build(Root::builder().build(LevelFilter::Off))?;

    log4rs::init_config(config)?;
    Ok(())
}