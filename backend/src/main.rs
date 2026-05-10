mod routes;
mod models; 

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    
    let database_url = std::env::var("DATABASE_URL")?; 
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(5).connect(&database_url).await?;

    println!("Database connected !");

    sqlx::migrate!("./migrations").run(&pool).await?;

    let app = routes::create_router(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}