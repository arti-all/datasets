<style>
	.contact-form .form-control{
	    border-radius:1rem;
	}
	.contact-form .btnContact {
	    width: 50%;
	    border: none;
	    border-radius: 1rem;
	    padding: 1.5%;
	    background: #007bff;
	    font-weight: 600;
	    color: #fff;
	    cursor: pointer;
	}
	.btnContactSubmit
	{
	    width: 50%;
	    border-radius: 1rem;
	    padding: 1.5%;
	    color: #fff;
	    background-color: #007bff;
	    border: none;
	    cursor: pointer;
	}	
	
</style>
 <form method="post" class="contact-form">
	 <div class="row">
                <h3>Drop Us a Message</h3>
							<p>	Feel free to contact us regarding any issues such as reporting a false positive or requesting the dataset of analyzed projects </p>
							</div>
               <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <input type="text" name="txtName" class="form-control" placeholder="Your Name *" value="" />
                        </div>
                        <div class="form-group">
                            <input type="text" name="txtEmail" class="form-control" placeholder="Your Email *" value="" />
                        </div>
                        <div class="form-group">
                            <textarea name="txtMsg" class="form-control" placeholder="Your Message *" style="width: 100%; height: 150px;"></textarea>
                        </div>
                        <div class="form-group">
                            <input type="submit" name="btnSubmit" class="btnContact btn-primary" value="Send Message" />
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                        </div>
                    </div>
                </div>
            </form>
<?php
if (isset($_POST['txtName']) && isset($_POST['txtEmail']) && isset($_POST['txtMsg']) ) {
	$name = $_POST['txtName'];
	$email = $_POST['txtEmail'];
	$message = $_POST['txtMsg'];
	if (strlen($name) > 3 && strlen($email) > 5 && strlen($message) > 5 ) {
		$ip = $_SERVER['REMOTE_ADDR'];
		$dt = date("Y-m-d h:i:sa");
		//-----
		$sql3 = "select *,TIMESTAMPDIFF(MINUTE,dt,NOW()) from tamas where ipaddr = '$ip' and TIMESTAMPDIFF(MINUTE,dt,NOW()) < 7";
    $result3 = $conn->query($sql3);
		if ( $result3->num_rows == 0 ) {
		//-----
		$stmt = $conn->prepare("INSERT INTO tamas (name, email, txt,ipaddr,dt) VALUES (?, ?, ?, ?, ?)");
		$stmt->bind_param("sssss", $name, $email, $message,$ip,$dt);
		$stmt->execute();
		echo "<div class='alert alert-info' role='alert'>Your message is sent. We will come back to you.</div>";
	  } else {
			echo "<div class='alert alert-danger' role='alert'>Please be patient. You just sent a message.</div>";
	  }
		
	} else {
		echo "<div class='alert alert-danger' role='alert'>Please fill in the form carefully</div>";
		
	}
	
	
	
	
} 

	
	
	
	
?>				