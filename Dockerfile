# Используем официальный образ Go на основе Alpine для легковесности
FROM golang:1.20-alpine

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файлы go.mod и go.sum для установки зависимостей
COPY go.mod go.sum ./

# Устанавливаем зависимости приложения
RUN go mod download

# Копируем весь исходный код в контейнер
COPY . .

# Компилируем приложение в бинарный файл с именем notification-service
RUN go build -o notification-service

# Указываем команду для запуска приложения
CMD ["./notification-service"]