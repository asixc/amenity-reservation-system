package com.amenity_reservation_system;

import com.amenity_reservation_system.model.AmenityType;
import com.amenity_reservation_system.model.Capacity;
import com.amenity_reservation_system.model.User;
import com.amenity_reservation_system.repos.CapacityRepository;
import com.amenity_reservation_system.repos.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class AmenityReservationSystemApplication {

  private final Map<AmenityType, Integer> initialCapacities =
      new HashMap<>() {
        {
          put(AmenityType.GYM, 20);
          put(AmenityType.POOL, 4);
          put(AmenityType.SAUNA, 1);
        }
      };

  public static void main(String[] args) {
    SpringApplication.run(AmenityReservationSystemApplication.class, args);
  }

  @Bean
  public CommandLineRunner loadData(
      UserRepository userRepository,
      CapacityRepository capacityRepository) {
    return (args) -> {
      userRepository.save(
          new User("Jose Alberto Lorenzo", "jotxee", bCryptPasswordEncoder().encode("12345")));

      for (AmenityType amenityType : initialCapacities.keySet()) {
        capacityRepository.save(new Capacity(amenityType, initialCapacities.get(amenityType)));
      }
    };
  }

  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
