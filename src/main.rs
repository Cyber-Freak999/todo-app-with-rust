use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
struct User {
    id: Option<Uuid>,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Task {
    id: Option<i32>,
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
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )",
        [],
    )
    .expect("Failed to create users table");

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

#[post("/register")]
async fn create_user(pool: web::Data<DbPool>, user: web::Json<User>) -> impl Responder {
    let conn = pool.get().expect("Failed to get a connection");

    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();
    let user_id = Uuid::new_v4();

    let result = conn.execute(
        "INSERT INTO users (id, username, password_hash) VALUES (?1, ?2, ?3)",
        (&user_id.to_string(), &user.username, &hashed_password),
    );

    match result {
        Ok(_) => HttpResponse::Ok().json(format!("User created with ID: {}", user_id)),
        Err(_) => HttpResponse::InternalServerError().json(MyError {
            message: "Failed to create user".into(),
        }),
    }
}

#[post("/login")]
async fn authenticate_user(pool: web::Data<DbPool>, user: web::Json<User>) -> impl Responder {
    let conn = pool.get().expect("Failed to get a connection");

    let mut stmt = conn
        .prepare("SELECT id, password_hash FROM users WHERE username = ?1")
        .unwrap();
    let mut rows = stmt.query(&[&user.username]).unwrap();

    if let Some(row) = rows.next().unwrap() {
        let stored_hash: String = row.get(1).unwrap();
        if verify(&user.password, &stored_hash).unwrap() {
            let user_id: String = row.get(0).unwrap();
            return HttpResponse::Ok().json(format!("Authenticated user with ID: {}", user_id));
        }
    }

    HttpResponse::Unauthorized().json(MyError {
        message: "Invalid credentials".into(),
    })
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
            .service(create_user)
            .service(authenticate_user)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
