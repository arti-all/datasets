<?php
set_time_limit(0);
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "crypto";

// Create connection
$conn = new mysqli($servername, $username, $password,$dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 
?>
<!doctype html>
<html lang="en">
  <head>
    <title>CryptoExplorer - a platform to explorer cryptographic API usages</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <link href="https://fonts.googleapis.com/css?family=Playfair+Display:400,700,900|Raleway" rel="stylesheet">

    <link rel="stylesheet" href="css/bootstrap.css">
    <link rel="stylesheet" href="css/animate.css">

    <link rel="stylesheet" href="fonts/fontawesome/css/font-awesome.min.css">

    <!-- Theme Style -->
    <link rel="stylesheet" href="css/style.css">
    <!-- Include EnlighterJS Styles -->
    <link rel="stylesheet" type="text/css" href="css/EnlighterJS.min.css" />

    <!-- Monospace Fonts on Google Webfonts !-->
    <link href='http://fonts.googleapis.com/css?family=Cutive+Mono|Roboto+Mono:400,700,400italic,500,500italic,700italic|Ubuntu+Mono:400,700,400italic,700italic|Droid+Sans+Mono|Source+Code+Pro:400,600' rel='stylesheet' type='text/css'>

    <!-- Include MooTools Framework -->
    <script type="text/javascript" src="css/MooTools.min.js"></script>

    <!-- Include EnlighterJS -->
    <script type="text/javascript" src="css/EnlighterJS.min.js"></script>

    <!-- Special Styles -->
    <style type="text/css">
        /* custom hover effect using specific css class */
				.EnlighterJS{
				   width: auto !important;
				   overflow-y: scroll !important;
				   word-wrap: normal !important;
					 height: 400px;
				}
				.EnlighterJS li{
				  white-space: pre !important;
				}
        .EnlighterJS.myHoverClass li:hover{
            background-color: #c0c0c0;
        }
    </style>

    <meta name="EnlighterJS" content="Advanced javascript based syntax highlighting" data-language="javascript" data-indent="2" data-selector-block="pre" data-selector-inline="code" />
  </head>
  <body>
    
    <header role="banner">
    </header>
    <!-- END header -->

    <section class="site-hero site-hero-innerpage2 overlay" data-stellar-background-ratio="0.5" style="background-image: url(images/big_image_1.jpg);">
      <div class="container">
        <div class="row align-items-center site-hero-inner2 justify-content-center">
          <div class="col-md-8 text-center">

            <div class="mb-5 element-animate">
							<?php
							function clean($string) {
							   $string = str_replace(' ', '', $string); // Replaces all spaces with hyphens.

							   return preg_replace('/[^A-Za-z0-9\-]/', '', $string); // Removes special chars.
							}
							if ( isset($_GET['api'])) {
							
							if (isset($_GET['mode'])) {
							$mode = $_GET['mode'];
							} else {
							$mode[0] = "misuse";
							$mode[1] = "";
							}
							$marks = array("misuse", "correct"); 
							foreach ($mode as $value) {
								if (!in_array($value, $marks)) 
								{ 
								  $mode[0] = "misuse";
									$mode[1] = "";
								} 
							}
							
							if (isset($_GET['misusetype'])) {
							$misusetype = $_GET['misusetype'];
							$xx = array("NeverTypeOfError", "ConstraintError","RequiredPredicateError","IncompleteOperationError"); 
							if (!in_array($misusetype, $xx)) 
							{ 
							  $misusetype = "*";
							} 
					  	} else {
							$misusetype = "*";
					  	}
							
							$api = $_GET['api'];
							$api = $conn->real_escape_string($api);
							$api = strip_tags($api);
							$api = clean($api);
							
							} else {
							$api = "";
							$mode[0] = "";
							$mode[1] = "";
							$misusetype= "";
							}
							?>
								  <a href="index.php"><h1>CryptoExplorer</h1></a>
              <p>Browse Java Cryptography Uses in Open-source Projects</p>
							       <form class="form-inline element-animate" action="search.php" id="search-form">
		              <label for="s" class="sr-only">Location</label>
		              <input type="text" class="form-control form-control-block search-input" name="api" id="autocomplete" value="<?php echo $api; ?>" placeholder="JCA API name e.g., MessageDigest" onFocus="geolocate()">
		              <button type="submit" class="btn btn-primary">Search</button>
									<div class="custom-control custom-checkbox">
									    <input type="checkbox" class="custom-control-input" id="defaultUnchecked" name="mode[]" <?php 
												foreach ($mode as $value) {
											if ($value == "misuse") echo "checked";
									      	}
												?> value="misuse">
									    <label class="custom-control-label" for="defaultUnchecked" style="color:white">Misuses .</label>
									</div>
									<div class="custom-control custom-checkbox">
									    <input type="checkbox" class="custom-control-input" id="defaultUnchecked2" name="mode[]" <?php 
												foreach ($mode as $value) {
											if ($value == "correct") echo "checked";
									      	}
												?> value="correct">
									    <label class="custom-control-label" for="defaultUnchecked2" style="color:white"> Correct uses</label>
									</div>
									<div class="class-control">
										<select name="misusetype" class="form-control" style="margin-left:10px;margin-top:5px"> 
									    <option value=""  selected>All misuse types</option>
										  <option value="NeverTypeOfError" <?php if ($misusetype == 'NeverTypeOfError') echo 'selected'; ?>>NeverTypeOfError</option>
										  <option value="ConstraintError" <?php if ($misusetype == 'ConstraintError') echo 'selected'; ?>>ConstraintError</option>
										  <option value="RequiredPredicateError" <?php if ($misusetype == 'RequiredPredicateError') echo 'selected'; ?>>RequiredPredicateError</option>
										  <option value="IncompleteOperationError" <?php if ($misusetype == 'IncompleteOperationError') echo 'selected'; ?>>IncompleteOperationError</option>
										</select>
									</div>
		            </form>
            </div>

            
          </div>
        </div>
      </div>
    </section>
    <!-- END section -->

    <section class="site-section" style="min-height: 800px;">
      <div class="container">
        <div class="row">
          <?php
							if ($api != '' && $mode[0] != '' ) {
								
							$sql2 = "SELECT projecturl,sub_project, file_path,GROUP_CONCAT(line_number) as ln from C_blamedev inner join c_projects on c_projects.id = c_blamedev.project_id where methodapi='$api' and s_object = 0 GROUP by projecturl,sub_project,file_path limit 0,20";
							$sql22 = "SELECT count(*) from C_blamedev inner join c_projects on c_projects.id = c_blamedev.project_id where methodapi='$api' and s_object = 0 GROUP by projecturl,sub_project,file_path";
							$sql3 = "SELECT projecturl,sub_project, file_path,GROUP_CONCAT(line_number) as ln from C_blamedev inner join c_projects on c_projects.id = c_blamedev.project_id where methodapi='$api' and s_object = 1 GROUP by projecturl,sub_project,file_path  limit 0,20";
							$sql33 = "SELECT count(*) from C_blamedev inner join c_projects on c_projects.id = c_blamedev.project_id where methodapi='$api' and s_object = 1 GROUP by projecturl,sub_project,file_path ";
							    if (count($mode) == 2) {
									if ($mode[0] == 'misuse' && $mode[1] == 'correct' )
									{
										echo '<div class="col-lg-6 col-md-6" style="background-color:#aadca94f">
            <div class="bg-white pl-lg-5 pl-0  pb-lg-5 pb-0 element-animate" data-animate-effect="fadeInRight">';
										
										$result2 = $conn->query($sql3);
										$result22 = $conn->query($sql33);
										
										$tt = $result22->num_rows;
										echo '<h5>'.$tt.' <span class="text-primary">correct uses</span>  	</h5>';
										
										while($row = $result2->fetch_assoc()) {
											$ln = $row['ln'];
											$proj = $row['projecturl'];
											$proj = str_replace("https://github.com","",$proj);
											$proj = substr($proj,strrpos($proj, '/') + 1);
											$proj = trim($proj);
											$sub = $row['sub_project'];
											$sub = trim($sub);
											$fl = $row['file_path'];
											$fl = substr($fl,strrpos($fl, '/') + 1);
								
											if ($sub == '')
											$file = file_get_contents('./JCA/'.$proj.'/'.$fl);
											else 
											$file = file_get_contents('./JCA/'.$proj.'/'.$sub.'/'.$fl);
												echo '				
										<pre data-enlighter-language="jquery" data-enlighter-highlight="'.$ln.'">
									 '.$file.'
										</pre>';
										echo '<a href=""> Download  </a>
										<hr>';
								
											}
										
										
										echo '</div></div>';
										//-------
										echo '<div class="col-lg-6 col-md-6" style="background-color:#e80d0d29">
											<div class="bg-white pl-lg-5 pl-0  pb-lg-5 pb-0 element-animate" data-animate-effect="fadeInRight">';
										
										$result2 = $conn->query($sql2);
										$result22 = $conn->query($sql22);
										
										$tt = $result22->num_rows;
										echo '<h5>'.$tt.' <span class="text-danger">misuses</span> </h5>';
										
										while($row = $result2->fetch_assoc()) {
											$ln = $row['ln'];
											$proj = $row['projecturl'];
											$proj = str_replace("https://github.com","",$proj);
											$proj = substr($proj,strrpos($proj, '/') + 1);
											$proj = trim($proj);
											$sub = $row['sub_project'];
											$sub = trim($sub);
											$fl = $row['file_path'];
											$fl = substr($fl,strrpos($fl, '/') + 1);
								
											if ($sub == '')
											$file = file_get_contents('./JCA/'.$proj.'/'.$fl);
											else 
											$file = file_get_contents('./JCA/'.$proj.'/'.$sub.'/'.$fl);
												echo '				
										<pre data-enlighter-language="jquery" data-enlighter-highlight="'.$ln.'">
									 '.$file.'
										</pre>';
										echo '<a href=""> Download  </a>
										<hr>';
								
											}
										
										
										echo '</div></div>';
										
										
										
									}
									} else {
										
										echo '<div class="col-lg-12 col-md-12">
											<div class="bg-white pl-lg-5 pl-0  pb-lg-5 pb-0 element-animate" data-animate-effect="fadeInRight">';
										
										if ($mode[0] == 'misuse') {
										$result2 = $conn->query($sql2);
										$result22 = $conn->query($sql22);
										
										$tt = $result22->num_rows;
										echo '<h4>'.$tt.' Java Files with <span class="text-danger">Misuses</span> </h4>';
									  } else { 
										$result2 = $conn->query($sql3);
										$result22 = $conn->query($sql33);
										
										$tt = $result22->num_rows;
										echo '<h4>'.$tt.' Java Files with <span class="text-primary">Correct</span> Uses 	</h4>';
									  }
										
										while($row = $result2->fetch_assoc()) {
											$ln = $row['ln'];
											$proj = $row['projecturl'];
											$proj = str_replace("https://github.com","",$proj);
											$proj = substr($proj,strrpos($proj, '/') + 1);
											$proj = trim($proj);
											$sub = $row['sub_project'];
											$sub = trim($sub);
											$fl = $row['file_path'];
											$fl = substr($fl,strrpos($fl, '/') + 1);
								
											if ($sub == '')
											$file = file_get_contents('./JCA/'.$proj.'/'.$fl);
											else 
											$file = file_get_contents('./JCA/'.$proj.'/'.$sub.'/'.$fl);
												echo $row['projecturl'].$row['sub_project'].'				
										<pre data-enlighter-language="jquery" data-enlighter-highlight="'.$ln.'">
									 '.$file.'
										</pre>';
										echo '<a href="dl.php"> Download  </a>
										<hr>';
								
											}
										
										
										
										echo '</div></div>';
										
										
									}
								
							
							}
							?>

        </div>
      </div>
    </section>
    <!-- END section -->

   
    <footer class="site-footer" style="margin-top:30px;margin-bottom:0px;padding:10px">
      <div class="container">
				        <div class="row justify-content-center">
				          <div class="col-md-7 text-center">
				            <!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
				Copyright &copy;<script>document.write(new Date().getFullYear());</script> All rights reserved 
				<!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
				  </div>
        </div>
      </div>
    </footer>

    <!-- END footer -->
    
    <!-- loader -->
    <div id="loader" class="show fullscreen"><svg class="circular" width="48px" height="48px"><circle class="path-bg" cx="24" cy="24" r="22" fill="none" stroke-width="4" stroke="#eeeeee"/><circle class="path" cx="24" cy="24" r="22" fill="none" stroke-width="4" stroke-miterlimit="10" stroke="#f4b214"/></svg></div>

    <script src="js/jquery-3.2.1.min.js"></script>
    <script src="js/jquery-migrate-3.0.0.js"></script>
    <script src="js/popper.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
    <script src="js/owl.carousel.min.js"></script>
    <script src="js/jquery.waypoints.min.js"></script>
    <script src="js/jquery.stellar.min.js"></script>

    <script src="js/main.js"></script>
  </body>
</html>