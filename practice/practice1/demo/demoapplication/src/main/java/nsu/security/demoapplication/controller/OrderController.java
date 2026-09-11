package nsu.security.demoapplication.controller;

import nsu.security.demoapplication.model.Order;
import nsu.security.demoapplication.repository.OrderRepository;
import nsu.security.demoapplication.repository.OrderJdbcRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;
import java.util.Set;


@RestController
public class OrderController {

    private final OrderRepository orderRepository;
    private final OrderJdbcRepository orderJdbcRepository;

    public OrderController(OrderRepository orderRepository, OrderJdbcRepository orderJdbcRepository) {
        this.orderRepository = orderRepository;
        this.orderJdbcRepository = orderJdbcRepository;
    }
    
    @GetMapping("/orders/{id}")
    public ResponseEntity<Order> getOrder(@PathVariable Long id) {
        return orderRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/orders")
    public Long createOrder(@RequestBody Order order) {
        Order saved = orderRepository.save(order);
        return saved.getId();
    }

    @PostMapping("/ordersql")
    public Long createOrderSql(@RequestBody Order order) {
        Order saved = orderRepository.insertOrder(order.getProductType().name(), order.getQuantity());
        return saved.getId();
    }

    @GetMapping("/orders/jdbc/{id}")
    public List<Order> getOrdersJdbc(@PathVariable String id) {
        return orderJdbcRepository.getOrders(id);
    }

    // Open Redirect
    // https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
    @GetMapping("/orders/redirect")
    public ResponseEntity<Void> redirectUnsafe(@RequestParam String url) {
        return ResponseEntity
                .status(HttpStatus.FOUND) // установить статус ответа 302
                .location(URI.create(url)) // куда перенаправить
                .build(); // собрать ответ без тела
    }

    // исправление: редирект только на заранее известный список путей
    Set<String> ALLOWED_REDIRECT_PATHS = Set.of(
            "/health",
            "/swagger-ui/index.html"
    );

    @GetMapping("/orders/redirect/safe")
    public ResponseEntity<Void> redirectSafe(@RequestParam String url) {
        if (!ALLOWED_REDIRECT_PATHS.contains(url)) {
            return ResponseEntity.badRequest().build();
        }

        return ResponseEntity
                .status(HttpStatus.FOUND)
                .location(URI.create(url))
                .build();
    }
}