package ca.bc.gov.nrs.api.helpers;

import ca.bc.gov.nrs.api.v1.entity.UserAddressEntity;
import ca.bc.gov.nrs.api.v1.entity.UserEntity;
import ca.bc.gov.nrs.api.v1.repository.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import net.datafaker.Faker;

import java.util.List;

@ApplicationScoped
public class TestHelper {
  private final UserRepository userRepository;
  private final Faker faker = new Faker();
  @Inject
  TestHelper(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Transactional(Transactional.TxType.REQUIRES_NEW)
  public void clearDatabase() {
    this.userRepository.deleteAll();
  }

  @Transactional(Transactional.TxType.REQUIRES_NEW)
  public UserEntity saveUser() {
    var name = faker.name();
    var email = faker.internet().emailAddress();
    UserEntity user = new UserEntity();
    user.setName(name.fullName());
    user.setEmail(email);
    this.userRepository.persist(user);
    return user;
  }

  @Transactional(Transactional.TxType.REQUIRES_NEW)
  public List<UserEntity> saveUsers(int size) {
    var users = new java.util.ArrayList<UserEntity>();
    for (int i = 0; i < size; i++) {
      var name = faker.name();
      var email = faker.internet().emailAddress();
      UserEntity user = new UserEntity();
      user.setName(name.fullName());
      user.setEmail(email);
      users.add(user);
    }
    try{
      // Persist users individually
      for (UserEntity user : users) {
        this.userRepository.persist(user);
      }
    }catch(Exception e){
      e.printStackTrace();
    }
    
    return users;
  }

  @Transactional(Transactional.TxType.REQUIRES_NEW)
  public UserAddressEntity saveUserAddress(UserEntity userEntity) {
    var savedUser = userRepository.findById(userEntity.getId());
    UserAddressEntity userAddress = new UserAddressEntity();
    userAddress.setUser(userEntity);
    userAddress.setStreet(faker.address().streetAddress());
    userAddress.setCity(faker.address().city());
    userAddress.setState(faker.address().state());
    userAddress.setZipCode(faker.address().zipCode());
    savedUser.getAddresses().add(userAddress);
    userRepository.persist(savedUser);
    return savedUser.getAddresses().get(0);
  }
}
