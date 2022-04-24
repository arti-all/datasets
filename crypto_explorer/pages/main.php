<?php
			if (isset($_POST['opradio']) && isset($_POST['code']) ) {
				$mamad1 = $_POST['opradio'];
				$mamad2 = $_POST['code'];
				$mamad3 = $_POST['kind'];
				
				
				
			} else {
				$mamad1 = "";
				$mamad2 = "";
				$mamad3 = "";
				
			}
	
?>
 <form class="form" method="POST" action="index.php" id="search-form">
	<div class="form-group">
									<!--<pre class="line-numbers" style="height:100px"><code class="language-java" >Mac mac = Mac.getInstance("HmacSHA1");
mac.init(key);
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");</code></pre>-->
		<textarea class="form-control" rows="5" cols="16" id="code" style="margin:5px" name="code" placeholder="A JCA API name or a code snippet" ><?php if (strlen($mamad2) != 0 ) echo $mamad2; ?></textarea>
	</div>
	<div class="form-group row">
		<div class="flag_style">
		    <div class="checkbox">
		    	<label>
		    		<span class="pull-left checkboxName">
		    			<strong>secure</strong>
		    		</span>
		    	</label>
		        <label class="switch">
		        	<input type="hidden" id="secure" title="kind" name="kind" value="secure">
		        	<input type="checkbox" id="buggy" title="kind" name="kind" <?php if ($mamad3 == "buggy") echo "checked"; ?> value="buggy">
		        	<span class="slider round"></span>
		        </label>
		        <label>
		    		<span class="pull-right checkboxName">
		    			<strong>buggy</strong>
		    		</span>
		    	</label> 
		    </div>	    
	  	</div>
		<div class="flag_style">
	    <div class="checkbox">
	    	<!--<label>
	    		<span class="pull-left checkboxName">
	    			<strong>API</strong>
	    		</span>
	    	</label>
	        <label class="switch">
	        	<input type="hidden" id="api" title="opradio" name="opradio" value="api">
	        	<input type="checkbox" id="cs" title="opradio" <php if ($mamad1 == "cs") echo "checked"; ?>  name="opradio" value="cs">
	        	<span class="slider round"></span>
	        </label>
	        <label>
	    		<span class="pull-right checkboxName">
	    			<strong>code snippet</strong>
	    		</span>
	    	</label> -->
	    </div>
	</div>	 </div>	<div class="form-group row">
	<div class="flag_styl2e">
	   
		<center>&nbsp;&nbsp;&nbsp;<button type="submit" class="btn btn-primary">Search</button>	</center></div>
	</div>
</div>
</form>
	<hr>
	</div>
</div>
</div>
</section>
<!-- END section -->
<section class="site-section2" style="min-height: 400px;">
  <div class="container">
    <div class="row">
    	<div class="col-lg-12"> 	
		<?php
		//---
				$xx = array("securerandom", "messagedigest","keystore","signature","mac","secretkeyspec","cipher","KeyPairGenerator","KeyPair","SecretKey","KeyGenerator","DHParameterSpec
","IvParameterSpec","GCMParameterSpec","AlgorithmParameters"); 
				$xx = array_map("strtolower", $xx);
		//---
		if (isset($_POST['kind']) && isset($_POST['code']) ) {
				//--------------- API ---------------
				$pieces = explode(" ", $_POST['code']);
				$ppp = explode(".", $_POST['code']);
				$pieces = array_merge($pieces,$ppp);
				//print_r($pieces);
				$pieces = array_map("trim", $pieces);
				$pieces = array_map("strtolower", $pieces);
				//print_r($pieces);
				$jca_f = array();
				foreach ($pieces as $val ) {
					if (in_array($val, $xx)) 
					{ 
						if (!in_array($val,$jca_f)) { array_push($jca_f, $val); }
					}
				}
			
				if ( count($jca_f) == 0 ) {
					echo "<div class='alert alert-danger' role='alert'>No JCA functions found in your input</div>";
					
				} else {
				//print_r($jca_f);
				//--------
				$sl = "";
				$qr = "";
				$n = 0;
				$nn = 0;
				foreach ($jca_f as $val) {
					if ( $n == 0)
						$sl = " methodapi = '".$val."' ";
						else 
						$sl .= " or methodapi = '".$val."' ";
						$n++;
				}
				foreach ($jca_f as $val) {
					if ( $nn == 0)
						$qr = "&methodapi=".$val."";
						else 
						$qr .= ",".$val."";
						$nn++;
				}
				$q = 0;
				///-------
				$correct = ($_POST['kind'] == "secure") ? "secure" : "buggy";
				$qr .= "&tp=$correct";
				//echo $correct;
				if ($correct == "secure") {
					$sql2 = "select * from ( SELECT C_projects_new.projecturl,C_projects_new.sub_project,tbl.*,std(line_number) as cc , GROUP_CONCAT(line_number) as ln FROM ( select * from C_blamedev_new where s_object = 1 ) as tbl inner join C_projects_new on tbl.project_id = C_projects_new.id where ".$sl." group by project_id,file_path,u_method having count(DISTINCT(methodapi)) = ".count($jca_f)." order by cc) as tabledp group by  methodapi, error_type, error_desc limit 3";
					$q = 1;
				} else {
					$sql2 = "select * from ( SELECT C_projects_new.projecturl,C_projects_new.sub_project,tbl.*,std(line_number) as cc , GROUP_CONCAT(line_number) as ln FROM ( select * from C_blamedev_new where s_object = 0 ) as tbl inner join C_projects_new on tbl.project_id = C_projects_new.id where ".$sl." group by project_id,file_path,u_method having count(DISTINCT(methodapi)) = ".count($jca_f)." order by cc ) as tabledp group by  methodapi, error_type, error_desc limit 3";
				$q = 2;
				}
				
				$result2 = $conn->query($sql2);
				if ( $result2->num_rows == 0 ) {
					echo "<div class='alert alert-secondary' role='alert'>No results found for your query. Here are suggested results by CryptoExplorer</div>";
						$sql2 = "select * from ( SELECT C_projects_new.projecturl,C_projects_new.sub_project,tbl.*,std(line_number) as cc , GROUP_CONCAT(line_number) as ln FROM ( select * from C_blamedev_new ) as tbl inner join C_projects_new on tbl.project_id = C_projects_new.id where ".$sl." group by project_id,file_path,u_method having count(DISTINCT(methodapi)) = ".count($jca_f)." order by cc ) as tabledp group by  methodapi, error_type, error_desc limit 3";
						$q = 3;
				$result2 = $conn->query($sql2);
				}
				//echo $sql2; //debug
				$tedad1 = $result2->num_rows;
				while($row = $result2->fetch_assoc())
				{
					$proj = $row['projecturl'];
					$proj = str_replace("https://github.com","",$proj);
					$proj = substr($proj,strrpos($proj, '/') + 1);
					$proj = trim($proj);
					$sub = $row['sub_project'];
					$sub = trim($sub);
					$fl = $row['file_path'];
					$fl_backup = $fl;										
					$fl = substr($fl,strrpos($fl, '/') + 1);
					$project_id = $row['project_id'];
					$ln = $row['ln'];	
					if (strlen($sub) == 0)
					$local= "./parts1-files/".$proj."/".$fl;
					else 
					$local= "./parts1-files/".$proj."/".$sub."/".$fl;
					if(file_exists($local))
					{
						$red = [];
						$green = [];
						$desc = [];
						//echo $local; //debug
						//echo "<br>";
						//---- get green / red lines
						if ($q == 1) 
						$sql3 = "select * from C_blamedev_new where project_id = $project_id and s_object = 1 and file_path like '%$fl' and ( ".$sl." )";
						else if ($q == 2)
							$sql3 = "select * from C_blamedev_new where project_id = $project_id and s_object = 0 and file_path like '%$fl' and ( ".$sl." )";
						else 
							$sql3 = "select * from C_blamedev_new where project_id = $project_id and file_path like '%$fl' and ( ".$sl." )";
							
						//echo $sql3; //debug
					$result3 = $conn->query($sql3);
					while($row2 = $result3->fetch_assoc())
					{
						if ($row2['s_object'] == 0) {
						  array_push($red, $row2['line_number']);
							array_push($desc, "At line ".$row2['line_number']." : ".$row2['error_type']." : ".$row2['error_desc'] );
							
						} else {
						  array_push($green, $row2['line_number']);
							
						}
						
						
					}
				  		$red = implode(',', $red);
				  		$green = implode(',', $green);															
						//---- end of getting red / green lines visibility
						$var_file = fopen($local,"r");

						if($red == '')
						{
							echo "<a href='#cp$project_id.$red' class='click_chevron visibility' cp='red' style='position:absolute; right:0; margin-top:0px;' id=".$red." disabled><i class='fa fa-chevron-up' aria-hidden='true'></i></a>";
						}
						else{
							echo "<a href='#cp$project_id.$red' class='click_chevron' cp='red' style='position:absolute; right:0; margin-top:0px;' id=".$red." disabled><i class='fa fa-chevron-up' aria-hidden='true'></i></a>";
						}

						if($green == ''){
							echo "<a href='#cp$project_id.$green' class='click_chevron visibility' cp='green' style='position:absolute; right:0; margin-top:20px;'  id=".$green."><i class='fa fa-chevron-down' aria-hidden='true'></i></a>";
						}
						else{
							echo "<a href='#cp$project_id.$green' class='click_chevron' cp='green' style='position:absolute; right:0; margin-top:20px;'  id=".$green."><i class='fa fa-chevron-down' aria-hidden='true'></i></a>";
						}
						echo '<pre class="line-numbers" data-line="'.$green.'" data-line2="'.$red.'"
							id="cp'.$project_id.'"><code class="language-java" >';
						while(! feof($var_file))
						{
							$local2 = fgets($var_file);
							echo htmlentities($local2);
						}
						echo'</code></pre><br>';
						fclose($var_file);
						echo'<div class="description_div"><p class="description_handle">More description</p>';
						foreach($desc as $val)
				echo'<p class="description" style="display: none;">'.$val.'</p>';
						
						echo "</div>";
						// 
					}
				}	
				if ( $tedad1 > 0 ) {
				echo '<br><center> 		<button type="submit" onclick="location.href=\'index.php?id=2'.$qr.'\'" class="btn btn-info">More examples</button>	</center> <br><br><br>';
			} else {
				echo "<Br><BR><br>";
			}
		  	}	
			} 
			//------------- NEXT PAGE
			if (isset($_GET['id']) && isset($_GET['methodapi']) && isset($_GET['tp']) ) {
				
					$pieces = explode(",", $_GET['methodapi']);
					$pieces = array_map("trim", $pieces);
					$pieces = array_map("strtolower", $pieces);
					$jca_f = array();
					foreach ($pieces as $val ) {
						if (in_array($val, $xx)) 
						{ 
							if (!in_array($val,$jca_f)) { array_push($jca_f, $val); }
						}
					}
			
					if ( count($jca_f) == 0 ) {
						echo "<div class='alert alert-danger' role='alert'>No JCA functions found in your input</div>";
					
					} else {
					//print_r($jca_f);
					//--------
					$sl = "";
					$qr = "";
					$n = 0;
					$nn = 0;
					foreach ($jca_f as $val) {
						if ( $n == 0)
							$sl = " methodapi = '".$val."' ";
							else 
							$sl .= " or methodapi = '".$val."' ";
							$n++;
					}
					foreach ($jca_f as $val) {
						if ( $nn == 0)
							$qr = "&methodapi=".$val."";
							else 
							$qr .= ",".$val."";
							$nn++;
					}
					$q = 0;
					///-------
					$correct = ($_GET['tp'] == "secure") ? "secure" : "buggy";
					$qr .= "&tp=$correct";
					//echo $correct;
					if ($correct == "secure") {
						$sql2 = "SELECT C_projects_new.projecturl,C_projects_new.sub_project,tbl.*,std(line_number) as cc , GROUP_CONCAT(line_number) as ln FROM ( select * from C_blamedev_new where s_object = 1 ) as tbl inner join C_projects_new on tbl.project_id = C_projects_new.id where ".$sl." group by project_id,file_path having count(DISTINCT(methodapi)) = ".count($jca_f)." order by cc limit 50";
						$q = 1;
					} else {
						$sql2 = "SELECT C_projects_new.projecturl,C_projects_new.sub_project,tbl.*,std(line_number) as cc , GROUP_CONCAT(line_number) as ln FROM ( select * from C_blamedev_new where s_object = 0 ) as tbl inner join C_projects_new on tbl.project_id = C_projects_new.id where ".$sl." group by project_id,file_path having count(DISTINCT(methodapi)) = ".count($jca_f)." order by cc limit 50";
					$q = 2;
					}
				
					$result2 = $conn->query($sql2);
					if ( $result2->num_rows == 0 ) {
						echo "<div class='alert alert-secondary' role='alert'>No results found for your query. Here are suggested results by CryptoExplorer</div>";
							$sql2 = "SELECT C_projects_new.projecturl,C_projects_new.sub_project,tbl.*,std(line_number) as cc , GROUP_CONCAT(line_number) as ln FROM ( select * from C_blamedev_new ) as tbl inner join C_projects_new on tbl.project_id = C_projects_new.id where ".$sl." group by project_id,file_path,u_method having count(DISTINCT(methodapi)) = ".count($jca_f)." order by cc limit 50";
							$q = 3;
					$result2 = $conn->query($sql2);
					}
					//echo $sql2; //debug
					
					$tedad1 = $result2->num_rows;
					while($row = $result2->fetch_assoc())
					{
						$proj = $row['projecturl'];
						$proj = str_replace("https://github.com","",$proj);
						$proj = substr($proj,strrpos($proj, '/') + 1);
						$proj = trim($proj);
						$sub = $row['sub_project'];
						$sub = trim($sub);
						$fl = $row['file_path'];
						$fl_backup = $fl;										
						$fl = substr($fl,strrpos($fl, '/') + 1);
						$project_id = $row['project_id'];
						$ln = $row['ln'];	
						if (strlen($sub) == 0)
						$local= "./parts1-files/".$proj."/".$fl;
						else 
						$local= "./parts1-files/".$proj."/".$sub."/".$fl;
						if(file_exists($local))
						{
							$red = [];
							$green = [];
							$desc = [];
							//echo $local; //debug
							//echo "<br>";
							//---- get green / red lines
							if ($q == 1) 
							$sql3 = "select * from C_blamedev_new where project_id = $project_id and s_object = 1 and file_path like '%$fl' and ( ".$sl." )";
							else if ($q == 2)
								$sql3 = "select * from C_blamedev_new where project_id = $project_id and s_object = 0 and file_path like '%$fl' and ( ".$sl." )";
							else 
								$sql3 = "select * from C_blamedev_new where project_id = $project_id and file_path like '%$fl' and ( ".$sl." )";
							
							//echo $sql3; //debug
						$result3 = $conn->query($sql3);
						while($row2 = $result3->fetch_assoc())
						{
							if ($row2['s_object'] == 0) {
							  array_push($red, $row2['line_number']);
								array_push($desc, "At line ".$row2['line_number']." : ".$row2['error_type']." : ".$row2['error_desc'] );
							
							} else {
							  array_push($green, $row2['line_number']);
							
							}
						
						
						}
					  $red = implode(',', $red);
					  $green = implode(',', $green);																		
							//---- end of getting red / green lines
							$var_file = fopen($local,"r");
					
							if($red == '')
							{
								echo "<a href='#cp$project_id.$red' class='click_chevron visibility' cp='red' style='position:absolute; right:0; margin-top:0px;' id=".$red." disabled><i class='fa fa-chevron-up' aria-hidden='true'></i></a>";
							}
							else{
								echo "<a href='#cp$project_id.$red' class='click_chevron' cp='red' style='position:absolute; right:0; margin-top:0px;' id=".$red." disabled><i class='fa fa-chevron-up' aria-hidden='true'></i></a>";
							}

							if($green == ''){
								echo "<a href='#cp$project_id.$green' class='click_chevron visibility' cp='green' style='position:absolute; right:0; margin-top:20px;'  id=".$green."><i class='fa fa-chevron-down' aria-hidden='true'></i></a>";
							}
							else{
								echo "<a href='#cp$project_id.$green' class='click_chevron' cp='green' style='position:absolute; right:0; margin-top:20px;'  id=".$green."><i class='fa fa-chevron-down' aria-hidden='true'></i></a>";
							}
					
							echo '<pre class="line-numbers" data-line="'.$green.'" data-line2="'.$red.'"
								id="cp'.$project_id.'"><code class="language-java" >';
							while(! feof($var_file))
							{
								$local2 = fgets($var_file);
								echo htmlentities($local2);
							}
							echo'</code></pre><br>';
							fclose($var_file);
							echo'<div class="description_div"><p class="description_handle">More description</p>';
							foreach($desc as $val) {
								if (strlen($val) > 22)
					echo'<p class="description" style="display: none;">'.$val.'</p>';
				}
							echo "</div><br>";
							// 
						}
					}	
					/*
					if ( $tedad1 > 0 ) {
					echo '<br><center> 		<button type="submit" onclick="location.href=\'index.php?id=2'.$qr.'\'" class="btn btn-info">More examples</button>	</center> <br><br><br>';
				} else {
					echo "<Br><BR><br>";
				} */
			  	}	
				} 
			
			
		?>
		</div>
	</div>
</div>