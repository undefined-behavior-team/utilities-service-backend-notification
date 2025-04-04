package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gocql/gocql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/segmentio/kafka-go"
)

// Notification — структура уведомления
type Notification struct {
	UUID      string    `json:"uuid"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// User — структура пользователя
type User struct {
	UUID string `json:"uuid"`
	Role string `json:"role"`
}

// ConnectionManager — менеджер WebSocket-соединений
type ConnectionManager struct {
	mu    sync.Mutex
	conns map[string]*websocket.Conn
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		conns: make(map[string]*websocket.Conn),
	}
}

func (cm *ConnectionManager) Add(uuid string, conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.conns[uuid] = conn
}

func (cm *ConnectionManager) Remove(uuid string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.conns, uuid)
}

func (cm *ConnectionManager) Get(uuid string) (*websocket.Conn, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	conn, ok := cm.conns[uuid]
	return conn, ok
}

// loadPublicKey — загрузка публичного ключа
func loadPublicKey() (*rsa.PublicKey, error) {
	pubKeyStr := os.Getenv("JWT_PUBLIC_KEY")
	if pubKeyStr == "" {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY not set")
	}

	if strings.Contains(pubKeyStr, "BEGIN PUBLIC KEY") {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyStr))
	}

	keyBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		pemStr := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", pubKeyStr)
		return jwt.ParseRSAPublicKeyFromPEM([]byte(pemStr))
	}

	key, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER public key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return rsaKey, nil
}

// authMiddleware — проверка JWT
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

		publicKey, err := loadPublicKey()
		if err != nil {
			log.Println("Error loading public key:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})
		if err != nil || !token.Valid {
			log.Println("Token validation error:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		uuid, _ := claims["id"].(string)
		role, _ := claims["role"].(string)
		if uuid == "" {
			http.Error(w, "UUID not found in token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "uuid", uuid)
		ctx = context.WithValue(ctx, "role", role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Настройте для безопасности
	},
}

// wsHandler — обработчик WebSocket
func wsHandler(cm *ConnectionManager, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uuid, ok := ctx.Value("uuid").(string)
	if !ok {
		http.Error(w, "UUID not found", http.StatusUnauthorized)
		return
	}

	role, _ := ctx.Value("role").(string)

	if err := ensureUserExists(uuid, role); err != nil {
		log.Println("Error ensuring user exists:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}

	cm.Add(uuid, conn)
	defer cm.Remove(uuid)
	defer conn.Close()

	// Получаем и отправляем все уведомления при подключении
	notifications, err := getAllNotifications(uuid)
	if err != nil {
		log.Println("Error fetching notifications:", err)
		return
	}
	if err := conn.WriteJSON(notifications); err != nil {
		log.Println("Error sending initial notifications:", err)
		return
	}

	// Ожидаем закрытия соединения
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}
	}
}

// getAllNotifications — получение всех уведомлений пользователя
func getAllNotifications(uuid string) ([]Notification, error) {
	session, err := cassandraSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	query := "SELECT timestamp, message FROM notifications WHERE uuid = ?"
	iter := session.Query(query, uuid).Iter()
	var notifications []Notification
	var timestamp time.Time
	var message string
	for iter.Scan(&timestamp, &message) {
		notifications = append(notifications, Notification{
			UUID:      uuid,
			Timestamp: timestamp,
			Message:   message,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return notifications, nil
}

// ensureUserExists — создание пользователя, если он отсутствует
func ensureUserExists(uuid, role string) error {
	session, err := cassandraSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var existingRole string
	query := "SELECT role FROM users WHERE uuid = ?"
	if err := session.Query(query, uuid).Scan(&existingRole); err != nil {
		if err == gocql.ErrNotFound {
			insertQuery := "INSERT INTO users (uuid, role) VALUES (?, ?)"
			return session.Query(insertQuery, uuid, role).Exec()
		}
		return err
	}
	return nil
}

// cassandraSession — создание сессии Cassandra
func cassandraSession() (*gocql.Session, error) {
	cluster := gocql.NewCluster(strings.Split(os.Getenv("CASSANDRA_HOST"), ",")...)
	cluster.Keyspace = os.Getenv("CASSANDRA_KEYSPACE")

	session, err := gocql.NewCluster(strings.Split(os.Getenv("CASSANDRA_HOST"), ",")...).CreateSession()
	if err != nil {
		return nil, err
	}

	keyspace := os.Getenv("CASSANDRA_KEYSPACE")
	err = session.Query(fmt.Sprintf(`
        CREATE KEYSPACE IF NOT EXISTS %s
        WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}
    `, keyspace)).Exec()
	session.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to create keyspace: %v", err)
	}

	session, err = cluster.CreateSession()
	if err != nil {
		return nil, err
	}

	err = session.Query(`
        CREATE TABLE IF NOT EXISTS users (
            uuid UUID PRIMARY KEY,
            role TEXT
        )
    `).Exec()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create users table: %v", err)
	}

	err = session.Query(`
        CREATE TABLE IF NOT EXISTS notifications (
            uuid UUID,
            timestamp TIMESTAMP,
            message TEXT,
            PRIMARY KEY (uuid, timestamp)
        ) WITH CLUSTERING ORDER BY (timestamp DESC)
    `).Exec()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create notifications table: %v", err)
	}

	return session, nil
}

// startKafkaConsumer — запуск Kafka-консьюмера
func startKafkaConsumer(cm *ConnectionManager) {
	brokers := strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	topic := os.Getenv("KAFKA_TOPIC")

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		Topic:   topic,
		GroupID: "notification-service",
	})

	for {
		m, err := r.ReadMessage(context.Background())
		if err != nil {
			log.Println("Error reading from Kafka:", err)
			continue
		}

		var notification Notification
		if err := json.Unmarshal(m.Value, &notification); err != nil {
			log.Println("Error unmarshaling notification:", err)
			continue
		}

		if err := saveNotification(notification); err != nil {
			log.Println("Error saving notification:", err)
			continue
		}

		conn, ok := cm.Get(notification.UUID)
		if ok {
			if err := conn.WriteJSON(notification); err != nil {
				log.Println("Error sending notification:", err)
			}
		}
	}
}

// saveNotification — сохранение уведомления в Cassandra
func saveNotification(n Notification) error {
	session, err := cassandraSession()
	if err != nil {
		return err
	}
	defer session.Close()

	query := "INSERT INTO notifications (uuid, timestamp, message) VALUES (?, ?, ?)"
	return session.Query(query, n.UUID, n.Timestamp, n.Message).Exec()
}

func main() {
	if os.Getenv("KAFKA_BROKERS") == "" {
		os.Setenv("KAFKA_BROKERS", "localhost:9092")
	}
	if os.Getenv("KAFKA_TOPIC") == "" {
		os.Setenv("KAFKA_TOPIC", "notifications")
	}
	if os.Getenv("CASSANDRA_HOST") == "" {
		os.Setenv("CASSANDRA_HOST", "localhost")
	}
	if os.Getenv("CASSANDRA_KEYSPACE") == "" {
		os.Setenv("CASSANDRA_KEYSPACE", "notifications_keyspace")
	}
	if os.Getenv("SERVER_PORT") == "" {
		os.Setenv("SERVER_PORT", "8080")
	}

	if _, err := cassandraSession(); err != nil {
		log.Fatalf("Failed to initialize Cassandra: %v", err)
	}

	cm := NewConnectionManager()

	go startKafkaConsumer(cm)

	http.Handle("/ws", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsHandler(cm, w, r)
	})))

	port := os.Getenv("SERVER_PORT")
	log.Println("Server started on :" + port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
