<?php
set_time_limit(0);
$servername = "localhost";
 $username = "crypto_mj";
 $password = "0fP79Sz7";
//$username = "root";
//$password = "";
$dbname = "crypto_mj";

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
    <!-- Monospace Fonts on Google Webfonts !-->
    <link href='http://fonts.googleapis.com/css?family=Cutive+Mono|Roboto+Mono:400,700,400italic,500,500italic,700italic|Ubuntu+Mono:400,700,400italic,700italic|Droid+Sans+Mono|Source+Code+Pro:400,600' rel='stylesheet' type='text/css'>
	<link href="prism2.css" rel="stylesheet" />
	<link rel="stylesheet" href="css/checkbox.css">
	<style>
		pre {
		   width: auto !important;
		   overflow-y: scroll !important;
		   /*word-wrap: normal !important;*/
		   height: 500px;
		}
		.description_div{
			background-color: #878787;
			color: #fafafa;
			padding: 5px 15px;
			margin-top: 0px;
		}
		/*.report{
			cursor: pointer;
		}*/
        .bbd{
            border: solid 2px #ffc107;
            -webkit-box-sizing: border-box !important;
            box-shadow: 1.2px 1.5px !important;
            -webkit-appearance: button;
        }
		.description a{
			color: #fafafa;
		}
		.border{
			border-bottom: dashed 1px #878787;
		}
		.description_handle{
			cursor: pointer;
	
		}
		.flag_style{
			display: inline-block !important;
			/*border: solid 1px;*/
			padding-top: 10px;
			margin-left: 15px;
			margin-right: 15px;
		}
		.visibility{
			visibility: hidden !important;
		}
	</style>   
	<script src="js/sweetalert.min.js"></script>
</head>
<body>
    <!-- <header role="banner">
    </header> -->
    <?php include'./pages/navbar.php';?>
    <!-- END header -->
    <section class="site-hero site-hero-innerpage2 overlay" data-stellar-background-ratio="0.5" style="background-image: url(images/big_image_1.jpg);">
      <div class="container">
        <div class="row align-items-center site-hero-inner2 justify-content-center">
          <div class="col-md-8 text-center">
            <div class="mb-5 element-animate">
				<a href="index.php"><h1>CryptoExplorer</h1></a>
              	<p>Browse Java Cryptography Uses in Open-source Projects</p>			     
            </div>
          </div>
        </div>
      </div>
    </section>
    <!-- END section -->
    <section class="site-section1" style="padding-top:2em">
      <div class="container">
        	<div class="row">
				<div class="col-lg-12 col-md-12">
				<?php
				if(isset($_GET['page']))
				{
					$page=$_GET['page'];
					if($page=='contactus'){include'./pages/contactus.php';}
				}
				else
				{
					include'./pages/main.php';
				}
				?>
				</div>
			</div>
		</div>		      
    </section>
    <!-- END section -->

   
    <footer class="site-footer" style="margin-top:30px;margin-bottom:0px;padding:10px">
      <div class="container">
				        <div class="row justify-content-center">
				          <div class="col-md-7 text-center">
				            <!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
				 &copy; <script>document.write(new Date().getFullYear());</script> CryptoExplorer
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
	<script src="prism.js"></script>
	<script type="text/javascript" src="js/custom.js"></script>
	<script type="text/javascript">
	$(function(){
		$(document.body).on('click','.report',function(){
			var report = $(this);
            var route_store = $(this).attr('store');
            swal({
                content: "input",
                title: "Report",
                text: "wurte something",
                icon: "info",
                buttons: true,
                dangerMode: false,
            })
            .then((willDelete) => {
            var row_id = $(this).attr('id');
            var input_report = $(document.body).find('.swal-content__input').val();
            if (willDelete) {
                swal("tanks for your report .", {
                  icon: "success",
                });

                $.ajax({
                    type: 'POST',
                    dataType: 'JSON',
                    url: route_store,
                    data: {
                         row_id:row_id,
                         input_report:input_report,
                        },
                    cache:false,
                    success: function(result){
                        if(result == true){
                        }
                        else{
                            report.css('backgroundColor','#F8D99A');
                        }   
                    },
                    error: function(error){
                            console.log(error);
                            report.css('backgroundColor','#F8A79A');
                    }
                }); 
              } 
              else {
                swal("it is not matter");
              }
            });
        });
	});
	</script>
  </body>
</html>