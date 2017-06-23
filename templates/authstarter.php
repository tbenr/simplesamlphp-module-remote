<?php
$this->data['header'] = $this->t('{remote:remote:select_source_header}');
$this->includeAtTemplateBase('includes/header.php');
?>

<br>

<?php
foreach($this->data['auth_methods'] as $auth_method) {
?>

<iframe src="<?php echo $auth_method['url'] . '?stateID=' . $this->data['stateid']; ?>" frameborder="0" seamless="seamless" style="height: 335px;" class="center-block" width="100%" marginheight="0">
</iframe>

<?php
 }
 
 $this->includeAtTemplateBase('includes/footer.php');