package web

import (
	"fmt"
	"net/http"
	"sync"
	"threatlens/internal/chat"
	storepkg "threatlens/internal/store"
	"threatlens/web/templates"

	"github.com/go-chi/chi/v5"
)

type Server struct {
	broker *SSEBroker
	router chi.Router
	db     *storepkg.Store
	chat   *chat.Chat
}

type SSEBroker struct {
	clients    map[chan string]struct{}
	register   chan chan string
	unregister chan chan string
	broadcast  chan string
	mu         sync.Mutex
}

func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		clients:    make(map[chan string]struct{}),
		register:   make(chan chan string),
		unregister: make(chan chan string),
		broadcast:  make(chan string, 10),
	}
}

func (b *SSEBroker) Run() {
	for {
		select {
		case client := <-b.register:
			b.mu.Lock()
			b.clients[client] = struct{}{}
			b.mu.Unlock()

		case client := <-b.unregister:
			b.mu.Lock()
			delete(b.clients, client)
			close(client)
			b.mu.Unlock()
		case msg := <-b.broadcast:
			b.mu.Lock()
			for client := range b.clients {
				client <- msg
			}
			b.mu.Unlock()
		}

	}
}

func (b *SSEBroker) Send(msg string) {
	b.broadcast <- msg
}

func (b *SSEBroker) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE Not supported", http.StatusInternalServerError)
		return
	}

	client := make(chan string, 10)
	b.register <- client
	defer func() { b.unregister <- client }()

	for {
		select {
		case msg := <-client:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func New(db *storepkg.Store) *Server {
	broker := NewSSEBroker()
	go broker.Run()

	s := &Server{
		broker: broker,
		router: chi.NewRouter(),
		db:     db,
	}

	s.router.Get("/", s.handleDashboard)
	s.router.Get("/events", s.broker.handleSSE)
	s.router.Post("/chat", s.handleChat)
	s.router.Get("/history", s.handleHistory)
	s.router.Get("/settings", s.handleSettingsPage)
	s.router.Post("/settings", s.handleSettingsSave)

	// serving static files
	s.router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	return s
}

func (s *Server) Start(addr string) error {
	return http.ListenAndServe(addr, s.router)

}

func (s *Server) Send(msg string) {
	s.broker.Send(msg)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	templates.Dashboard().Render(r.Context(), w)
}
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	question := r.FormValue("question")
	if question == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// load api key and model from db
	apiKey, _ := s.db.GetSettings("api_key")
	model, _ := s.db.GetSettings("model")

	if apiKey == "" || model == "" {
		fmt.Fprintf(w, `<div class="text-red-400 text-sm">API key or model not set. Go to /settings first.</div>`)
		return
	}

	detections, _ := s.db.GetRecentDetections(20)

	c := chat.New(apiKey, model)
	c.LoadContext(detections)

	answer, err := c.Ask(question)
	if err != nil {
		fmt.Fprintf(w, `<div class="text-red-400 text-sm">Error: %s</div>`, err.Error())
		return
	}
	fmt.Fprintf(w, `
    <div class="flex justify-start gap-2 chat-bubble-ai">
        <div class="w-8 h-8 rounded-lg bg-slate-700 flex-shrink-0 flex items-center justify-center">
            <span class="material-symbols-outlined text-blue-300 text-sm">smart_toy</span>
        </div>
        <div class="max-w-[85%] tonal-card text-slate-200 p-3 rounded-xl rounded-tl-none text-sm">%s</div>
    </div>
`, answer)

}
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	apiKey, _ := s.db.GetSettings("api_key")
	model, _ := s.db.GetSettings("model")
	templates.Settings(apiKey, model).Render(r.Context(), w)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	api_key := r.FormValue("api_key")
	model := r.FormValue("model")

	s.db.SaveSetting("api_key", api_key)
	s.db.SaveSetting("model", model)

	s.chat = chat.New(api_key, model)

	w.Header().Set("HX-Trigger", "settingsSaved")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Saved."))
}
