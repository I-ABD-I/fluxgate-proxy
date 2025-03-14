use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;

pub(super) fn create_logger(verbose: bool) -> anyhow::Result<()> {
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} {h({l})} [{h({t})}] {m}{n}",
        )))
        .build();

    let file = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} {h({l})} [{h({t})}] {m}{n}",
        )))
        .build("log/fluxgate.log")?;

    let fluxgate_logger = Logger::builder()
        .appenders(["console", "file"])
        .build("fluxgate", LevelFilter::Debug);

    let tls_logger_level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let tls_logger = Logger::builder()
        .appenders(["console", "file"])
        .build("tls", tls_logger_level);

    let config = Config::builder()
        .appender(Appender::builder().build("console", Box::new(console)))
        .appender(Appender::builder().build("file", Box::new(file)))
        .loggers([fluxgate_logger, tls_logger])
        .build(Root::builder().build(LevelFilter::Off))?;

    log4rs::init_config(config)?;
    Ok(())
}
