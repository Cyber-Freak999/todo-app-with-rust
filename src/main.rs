use actix_web::{
    delete, get, post, put,
    web::{self, get},
    App, HttpResponse, HttpServer, Responder,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, Result};
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

#[derive(serde::Deserialize)]
struct UpdateTaskStatus {
    status: String,
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

#[get("/tasks/user/{user_id}")]
async fn get_task(pool: web::Data<DbPool>, user_id: web::Path<Uuid>) -> impl Responder {
    let conn = pool.get().expect("Failed to get a connection");
    let user_id_str = user_id.to_string();

    let mut stmt = conn
        .prepare("SELECT id, completed, content, user_id FROM tasks WHERE user_id = ?1")
        .unwrap();

    let task_iter = stmt
        .query_map([&user_id_str], |row| {
            Ok(Task {
                id: row.get(0)?,
                completed: row.get(1)?,
                content: row.get(2)?,
                user_id: Uuid::parse_str(row.get::<_, String>(3)?.as_str()).unwrap(),
            })
        })
        .unwrap();

    let tasks: Vec<Task> = task_iter.filter_map(|result| result.ok()).collect();

    if tasks.is_empty() {
        return HttpResponse::NotFound().json(MyError {
            message: format!("No tasks found for user_id: {}", user_id_str),
        });
    }

    HttpResponse::Ok().json(tasks)
}

#[put("/tasks/user/{user_id}/{task_id}")]
async fn update_task(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    task_id: web::Path<i32>,
    task_completed: web::Json<UpdateTaskStatus>,
) -> impl Responder {
    let conn = pool.get().expect("Failed to get a connection");
    let user_id_str = user_id.to_string();
    let task_id_str = task_id.into_inner();
    let task_completed_str = task_completed.into_inner().status;

    // let stmt = conn.execute(
    //    "UPDATE tasks SET completed=?1 WHERE id=?2 AND user_id=?3",
    //    params![task_completed_str, task_id_str, user_id_str],
    //);
    
    let stmt = conn.execute(
    "UPDATE tasks SET completed=$1 WHERE id=$2 AND user_id=$3",
    (&task_completed_str, &task_id_str, &user_id_str),
	);

    match stmt {
        Ok(_) => HttpResponse::Ok().json(format!(
            "Updated task with id: {} for user_id: {}",
            task_id_str, user_id_str
        )),
        Err(_) => HttpResponse::NotFound().json(MyError {
            message: format!(
                "Task with id {} for user_id {} not found",
                task_id_str, user_id_str
            ),
        }),
    }
}

#[delete("/tasks/user/{user_id}/{task_id}")]
async fn delete_task(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    task_id: web::Path<i32>,
) -> impl Responder {
    let conn = pool.get().expect("Failed to get a connection");
    let user_id_str = user_id.to_string();
    let task_id_str = task_id.into_inner();

    let stmt = conn.execute(
        "DELETE FROM task WHERE id=?1 AND user_id=?2",
        (&task_id_str, &user_id_str),
    );

    match stmt {
        Ok(_) => HttpResponse::Ok().json(format!(
            "Deleted task with id: {} for user_id: {}",
            task_id_str, user_id_str
        )),
        Err(_) => HttpResponse::NotFound().json(MyError {
            message: format!(
                "Task with id {} for user_id {} not found",
                task_id_str, user_id_str
            ),
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
            .service(get_task)
            .service(update_task)
            .service(delete_task)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
