use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use bytes::Bytes;
use dotenv::dotenv;
use ethers::abi::Token;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::core::rand::random;
use ethers::prelude::*;
use ethers::utils::{hex, keccak256, parse_units};
use log::{error, info, warn};
use rayon::prelude::*;
use serde::Deserialize;
use tokio;

use crate::initialization::{print_banner, setup_logger};

mod initialization;

static TIMES: AtomicUsize = AtomicUsize::new(0);

const CURRENT_CHALLENGE: &str =
    "0x7245544800000000000000000000000000000000000000000000000000000000";

#[derive(Deserialize, Debug)]
pub struct Config {
    pub rpc_url: String,
    pub private_key: String,
    pub tick: String,
    pub amt: String,
    pub difficulty: String,
    pub count: u32,
    pub max_fee_per_gas: f64,
    pub max_priority_fee_per_gas: f64,
}

impl Config {
    pub fn get_random_data(&self, potential_solution: &str) -> String {
        // data:application/json,{"p":"rerc-20","op":"mint","tick":"rETH","id":"0x4a43edd88cf60d1f0282141a3423128579380eec6e2e13efb0ae7ba36d1e35f1","amt":"10000"}
        let data = format!(
            "data:application/json,{{\"p\":\"rerc-20\",\"op\":\"mint\",\"tick\":\"{}\",\"id\":\"{}\",\"amt\":\"{}\"}}",
            self.tick, potential_solution, self.amt
        );
        data
    }
}

pub struct GasPrice {
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    setup_logger()?;
    print_banner();

    info!("开始执行任务");
    warn!("Author:[𝕏] @0xNaiXi");
    warn!("Author:[𝕏] @0xNaiXi");
    warn!("Author:[𝕏] @0xNaiXi");
    // 解析 .env 文件
    let config = envy::from_env::<Config>()?;
    let provider = Provider::<Http>::try_from(&config.rpc_url)?;
    let chain_id = provider.get_chainid().await?;
    let private_key = config.private_key.clone();
    let wallet = private_key
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id.as_u64());
    let address = wallet.address();
    let mut nonce = provider.get_transaction_count(address, None).await?;

    info!("当前钱包地址: {:?}", address);
    info!("当前链ID: {:?}", chain_id);
    info!("钱包nonce: {:?}", nonce);
    let pu = parse_units(config.max_fee_per_gas, "gwei").unwrap();
    let max_fee_per_gas = U256::from(pu);
    let pu = parse_units(config.max_priority_fee_per_gas, "gwei").unwrap();
    let max_priority_fee_per_gas = U256::from(pu);
    let gas_price = GasPrice {
        max_fee_per_gas,
        max_priority_fee_per_gas,
    };
    let mut success = 0;
    tokio::spawn(async move {
        loop {
            let last_times = TIMES.load(Ordering::Relaxed) as u64;
            tokio::time::sleep(Duration::new(10, 0)).await;
            let rate = (TIMES.load(Ordering::Relaxed) as u64 - last_times) / 10;
            warn!(
                "计算hash总次数 {}  速率 {} hashes/s",
                TIMES.load(Ordering::Relaxed),
                rate
            );
        }
    });


    while success < config.count {
        if make_tx(&provider, &wallet, &config, &gas_price, nonce).await? {
            success = success + 1;
        }
        nonce = nonce + 1;
    }

    info!("任务执行完毕");

    //编译成exe 取消下面的屏蔽 不让程序关闭窗口 不然的话 会执行完任务 直接关闭窗口 无法看输出的日志了
    //tokio::time::sleep(Duration::new(1000, 0)).await;
    Ok(())
}

fn solve_challenge(challenge: &str, difficulty: &str) -> Option<String> {
    rayon::iter::repeat(()).find_map_any(|_| {
        TIMES.fetch_add(1, Ordering::Relaxed);
        let random_bytes: [u8; 32] = random();
        let hashed_solution = hex::encode_prefixed(keccak256(Bytes::from(
            abi::encode_packed(&[
                Token::Bytes(ethers::abi::Bytes::from(random_bytes)),
                Token::Bytes(hex::decode(challenge).unwrap()),
            ])
            .unwrap(),
        )));
        let flag = hashed_solution.starts_with(difficulty);
        if flag {
            let potential_solution = hex::encode_prefixed(random_bytes);
            Some(potential_solution)
        } else {
            None
        }
    })
}

async fn make_tx(
    provider: &Provider<Http>,
    wallet: &Wallet<SigningKey>,
    config: &Config,
    gas_price: &GasPrice,
    nonce: U256,
) -> Result<bool, Box<dyn std::error::Error>> {
    let chain_id = wallet.chain_id();
    let (flag, potential_solution) =
        if let Some(solution) = solve_challenge(CURRENT_CHALLENGE, &config.difficulty) {
            (true, solution)
        } else {
            info!("nonce: {:?} 生成随机值失败", nonce);
            (false, String::new()) // 这里假设 potential_solution 是 String 类型，你需要根据实际情况替换为正确的类型
        };

    if !flag {
        return Ok(false);
    }

    let data = Bytes::from(config.get_random_data(&potential_solution));
    let tx = Eip1559TransactionRequest::new()
        .chain_id(chain_id)
        .from(wallet.address())
        .to(wallet.address())
        .value(0)
        .max_fee_per_gas(gas_price.max_fee_per_gas)
        .max_priority_fee_per_gas(gas_price.max_priority_fee_per_gas)
        .gas(50000)
        .nonce(nonce)
        .data(data)
        .access_list(vec![])
        .into();
    let signature = wallet.sign_transaction_sync(&tx)?;
    let signed_tx = tx.rlp_signed(&signature);
    let tx_hash = provider.send_raw_transaction(signed_tx).await;
    match tx_hash {
        Ok(tx_hash) => {
            info!("nonce: {:?} 交易发送成功: {:?}", nonce, tx_hash.tx_hash());
        }
        Err(e) => {
            // replacement transaction underpriced
            // nonce too low
            error!("nonce: {:?}  交易发送失败: {:?} ", nonce, e);
        }
    };
    Ok(true)
}
