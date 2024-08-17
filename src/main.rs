use core::task;
use std::fmt::format;

use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
struct User {
    id: Uuid,
    username: String,
    password_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Task {
    id: i32,
    completed: String,
    content: String,
    user_id: Uuid,
}

#[derive(Debug, Serialize)]
struct MyError {
    message: String,
}

impl From<rusqlite::Error> for MyError {
    fn from(err: rusqlite::Error) -> MyError {
        MyError {
            message: format!("{}", err),
        }
    }
}

type DbPool = Pool<SqliteConnectionManager>;

fn init_db(conn: &Connection) {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            completed TEXT NOT NULL,
            content TEXT,
            user_id TEXT NOT NULL,
            CONSTRAINT is_completed CHECK (completed IN ('Y', 'N'))
            FOREIGN KEY(user_id) REFERENCES users(id)
        )",
        [],
    )
    .expect("Failed to create tasks table");
}

#[post("/tasks")]
async fn create_task(pool: web::Data<DbPool>, task: web::Json<Task>) -> impl Responder {
    let conn = pool.get().expect("Failed to get a connection");

    let result = conn.execute(
        "INSERT INTO tasks (completed, content, user_id) VALUES (?1, ?2, ?3)",
        (&task.completed, &task.content, &task.user_id.to_string()),
    );

    match result {
        Ok(_) => HttpResponse::Ok().json(task.into_inner()),
        Err(_) => HttpResponse::InternalServerError().json(MyError {
            message: "Failed to create task".into(),
        }),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let manager = SqliteConnectionManager::file("todo.db");
    let pool = Pool::new(manager).expect("Failed to create pool");

    {
        let conn = pool.get().expect("Failed to get a connection");
        init_db(&conn);
    }

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone())) // Share the pool with all routes
            .service(create_task)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
