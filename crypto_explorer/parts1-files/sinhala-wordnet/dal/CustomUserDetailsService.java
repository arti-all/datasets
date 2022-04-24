package org.sinhala.wordnet.wordnetDB.core;

import org.sinhala.wordnet.wordnetDB.config.SpringMongoConfig;
import org.sinhala.wordnet.wordnetDB.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class CustomUserDetailsService implements UserDetailsService {

	private MongoTemplate mongoTemplate;

	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		User user = getUserDetail(username);
		if (user != null) {
			if (user.isVerified()) {
				org.springframework.security.core.userdetails.User userDetail = new org.springframework.security.core.userdetails.User(
						user.getUsername(), user.getPassword(), true, true,
						true, true, getAuthorities(user.getRole()));
				return userDetail;
			} else {
				return new org.springframework.security.core.userdetails.User(
						user.getUsername(), user.getPassword(), false, true,
						true, true, getAuthorities(user.getRole()));
			}
		} else {
			org.springframework.security.core.userdetails.User userDetail = new org.springframework.security.core.userdetails.User(
					username, "dummyPassword", true, true, true, true,
					getAuthorities(0));
			return userDetail;
		}

	}

	@Autowired
	public void setMongoTemplate(MongoTemplate mongoTemplate) {
		this.mongoTemplate = mongoTemplate;
	}

	public List<GrantedAuthority> getAuthorities(Integer role) {
		List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>();
		if (role.intValue() == 1) {
			authList.add(new SimpleGrantedAuthority("ROLE_USER"));
			authList.add(new SimpleGrantedAuthority("ROLE_EVALUATOR"));
			authList.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		} else if (role.intValue() == 2) {
			authList.add(new SimpleGrantedAuthority("ROLE_USER"));
			authList.add(new SimpleGrantedAuthority("ROLE_EVALUATOR"));
		} else if (role.intValue() == 3) {
			authList.add(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return authList;
	}

	public User getUserDetail(String username) {
		ApplicationContext ctx = new AnnotationConfigApplicationContext(
				SpringMongoConfig.class);
		MongoOperations mongoOperation = (MongoOperations) ctx
				.getBean("mongoTemplate");
		User user = mongoOperation.findOne(new Query(Criteria.where("username")
				.is(username).and("verified").is(true)), User.class);
		if (user == null) {
			User userNotVerified = mongoOperation.findOne(new Query(Criteria
					.where("username").is(username)), User.class);
			if (userNotVerified == null) {
				((AbstractApplicationContext) ctx).close();
				return null;
			}
			((AbstractApplicationContext) ctx).close();
			return userNotVerified;
		}
		((AbstractApplicationContext) ctx).close();
		return user;
	}

	public User getUserDetailByKey(String key) {
		ApplicationContext ctx = new AnnotationConfigApplicationContext(
				SpringMongoConfig.class);
		MongoOperations mongoOperation = (MongoOperations) ctx
				.getBean("mongoTemplate");
		User user = mongoOperation.findOne(
				new Query(Criteria.where("key").is(key)), User.class);
		((AbstractApplicationContext) ctx).close();
		return user;
	}

	public void addUserDetail(User user) {
		ApplicationContext ctx = new AnnotationConfigApplicationContext(
				SpringMongoConfig.class);
		MongoOperations mongoOperation = (MongoOperations) ctx
				.getBean("mongoTemplate");

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(user.getPassword().getBytes("UTF-8"));
			byte[] hash = digest.digest();
			
			StringBuffer sb = new StringBuffer();
	        for (int i = 0; i < hash.length; i++) {
	         sb.append(Integer.toString((hash[i] & 0xff) + 0x100, 16).substring(1));
	        }
	        
	        user.setPassword(sb.toString());
	        
		} catch (NoSuchAlgorithmException ex) {
			ex.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mongoOperation.save(user);
		((AbstractApplicationContext) ctx).close();
	}

	public void confirmUser(User user) {
		user.setVerified(true);
		ApplicationContext ctx = new AnnotationConfigApplicationContext(
				SpringMongoConfig.class);
		MongoOperations mongoOperation = (MongoOperations) ctx
				.getBean("mongoTemplate");

		Query query = new Query();
		query.addCriteria(Criteria.where("key").is(user.getKey()));
		Update update = new Update();
		update.set("verified", true);

		mongoOperation.findAndModify(query, update,
				new FindAndModifyOptions().returnNew(true), User.class);
		((AbstractApplicationContext) ctx).close();
	}

	public boolean isUsernameExist(String username) {
		ApplicationContext ctx = new AnnotationConfigApplicationContext(
				SpringMongoConfig.class);
		MongoOperations mongoOperation = (MongoOperations) ctx
				.getBean("mongoTemplate");
		User user = mongoOperation.findOne(new Query(Criteria.where("username")
				.is(username).and("verified").is(true)), User.class);

		if (user == null) {
			((AbstractApplicationContext) ctx).close();
			return false;
		}
		((AbstractApplicationContext) ctx).close();
		return true;
	}

	public boolean isEmailExist(String email) {
		ApplicationContext ctx = new AnnotationConfigApplicationContext(
				SpringMongoConfig.class);
		MongoOperations mongoOperation = (MongoOperations) ctx
				.getBean("mongoTemplate");
		User user = mongoOperation.findOne(new Query(Criteria.where("email")
				.is(email).and("verified").is(true)), User.class);

		if (user == null) {
			((AbstractApplicationContext) ctx).close();
			return false;
		}
		((AbstractApplicationContext) ctx).close();
		return true;
	}
}