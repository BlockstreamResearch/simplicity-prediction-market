use std::str::FromStr;

use sqlx::{
    AnyPool, Row,
    any::{AnyPoolOptions, AnyRow},
    sqlite::SqliteConnectOptions,
};

use super::{AppError, Prediction, price::PriceMarket};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const SELECT_PREDICTIONS: &str = "SELECT p.id, p.title, p.deadline, p.created_at, \
        m.feed_id, m.decimals, m.strike, m.above, m.opens_at, m.claim_grace, \
        m.house_script_pubkey, m.tick_asset_id, m.verifier_asset_id, m.storm_eye_asset_id \
    FROM predictions p JOIN price_markets m ON m.prediction_id = p.id";

#[derive(Clone)]
pub(super) struct Database {
    pool: AnyPool,
}

impl Database {
    pub(super) async fn connect(url: &str, max_connections: u32) -> Result<Self, AppError> {
        sqlx::any::install_default_drivers();
        if url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(url)?;
            if let Some(parent) = options
                .get_filename()
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let pool = AnyPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await?;
        MIGRATOR.run(&pool).await?;

        Ok(Self { pool })
    }

    pub(super) async fn list(&self) -> Result<Vec<Prediction>, sqlx::Error> {
        sqlx::query(&format!("{SELECT_PREDICTIONS} ORDER BY p.created_at, p.id"))
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(decode)
            .collect()
    }

    pub(super) async fn find(&self, id: &str) -> Result<Option<Prediction>, sqlx::Error> {
        sqlx::query(&format!("{SELECT_PREDICTIONS} WHERE p.id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(decode)
            .transpose()
    }

    pub(super) async fn insert(&self, prediction: &Prediction) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO predictions \
             (id, title, deadline, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&prediction.id)
        .bind(&prediction.title)
        .bind(signed(prediction.deadline)?)
        .bind(signed(prediction.created_at)?)
        .execute(&mut *transaction)
        .await?;
        let inserted = result.rows_affected() == 1;
        if inserted {
            let price = &prediction.price;
            sqlx::query(
                "INSERT INTO price_markets \
                 (prediction_id, feed_id, decimals, strike, above, opens_at, claim_grace, \
                  house_script_pubkey, tick_asset_id, verifier_asset_id, storm_eye_asset_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(&prediction.id)
            .bind(i64::from(price.feed_id))
            .bind(i64::from(price.decimals))
            .bind(&price.strike)
            .bind(i64::from(price.above))
            .bind(signed(price.opens_at)?)
            .bind(signed(price.claim_grace)?)
            .bind(&price.house_script_pubkey)
            .bind(&price.tick_asset_id)
            .bind(&price.verifier_asset_id)
            .bind(&price.storm_eye_asset_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;

        Ok(inserted)
    }

    #[cfg(test)]
    pub(super) async fn set_deadline(&self, id: &str, deadline: u64) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE predictions SET deadline = $2 WHERE id = $1")
            .bind(id)
            .bind(signed(deadline)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn decode(row: &AnyRow) -> Result<Prediction, sqlx::Error> {
    let price = PriceMarket {
        feed_id: u32::try_from(row.try_get::<i64, _>("feed_id")?).map_err(decode_error)?,
        decimals: u32::try_from(row.try_get::<i64, _>("decimals")?).map_err(decode_error)?,
        strike: row.try_get("strike")?,
        above: row.try_get::<i64, _>("above")? != 0,
        opens_at: unsigned(row.try_get("opens_at")?)?,
        claim_grace: unsigned(row.try_get("claim_grace")?)?,
        house_script_pubkey: row.try_get("house_script_pubkey")?,
        tick_asset_id: row.try_get("tick_asset_id")?,
        verifier_asset_id: row.try_get("verifier_asset_id")?,
        storm_eye_asset_id: row.try_get("storm_eye_asset_id")?,
    };

    Ok(Prediction {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        deadline: unsigned(row.try_get("deadline")?)?,
        created_at: unsigned(row.try_get("created_at")?)?,
        price,
    })
}

fn signed(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value).map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

fn unsigned(value: i64) -> Result<u64, sqlx::Error> {
    u64::try_from(value).map_err(decode_error)
}

fn decode_error(error: std::num::TryFromIntError) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn database_contract(database: Database) {
        let price = Prediction {
            id: "22".repeat(32),
            title: "BTC/USD reaches its target".into(),
            deadline: 2000,
            created_at: 1000,
            price: PriceMarket {
                feed_id: u32::MAX,
                decimals: 8,
                strike: u64::MAX.to_string(),
                above: false,
                opens_at: 1000,
                claim_grace: 600,
                house_script_pubkey: "51".into(),
                tick_asset_id: "33".repeat(32),
                verifier_asset_id: "44".repeat(32),
                storm_eye_asset_id: "55".repeat(32),
            },
        };
        assert!(database.insert(&price).await.unwrap());
        assert_eq!(database.find(&price.id).await.unwrap(), Some(price.clone()));
        assert!(database.find("missing").await.unwrap().is_none());

        let mut changed = price.clone();
        changed.title = "Changed".into();
        assert!(!database.insert(&changed).await.unwrap());
        assert_eq!(database.find(&price.id).await.unwrap(), Some(price.clone()));

        let archived_id = "11".repeat(32);
        sqlx::query(
            "INSERT INTO predictions (id, title, deadline, created_at, resolution_occurred_at, resolution_signature) \
             VALUES ($1, 'Archived event', 2000, 1000, 1500, 'archived-signature')",
        )
        .bind(&archived_id)
        .execute(&database.pool)
        .await
        .unwrap();
        assert!(database.find(&archived_id).await.unwrap().is_none());
        assert_eq!(database.list().await.unwrap(), vec![price.clone()]);
        let signature: String =
            sqlx::query_scalar("SELECT resolution_signature FROM predictions WHERE id = $1")
                .bind(&archived_id)
                .fetch_one(&database.pool)
                .await
                .unwrap();
        assert_eq!(signature, "archived-signature");

        let mut invalid = price;
        invalid.id = "66".repeat(32);
        invalid.price.opens_at = u64::MAX;
        assert!(database.insert(&invalid).await.is_err());
        assert!(database.find(&invalid.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_storage_contract() {
        database_contract(Database::connect("sqlite::memory:", 1).await.unwrap()).await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing to an empty disposable PostgreSQL database"]
    async fn postgres_storage_contract() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
        database_contract(Database::connect(&url, 5).await.unwrap()).await;
    }
}
