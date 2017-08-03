<?php
$this->data['header'] = $this->t($this->data['auth_group']['label_tag']);
$this->includeAtTemplateBase('remote:includes/header.php');

$auth_methods = $this->data['auth_group']['auth_methods'];
$auth_preferred_method = $this->data['preferred'];
?>

<script type="text/javascript">
var default_tab = 0;

var urls  = [];
<?php
$cnt = 0;
foreach($auth_methods as $auth_method) {
    echo 'urls.push(\'' . $auth_method['url'] . '?stateID=' . $this->data['stateid'] . '\');';
    echo "\n";
    if($auth_method['label_tag'] == $auth_preferred_method) {
        echo 'default_tab = . $cnt . ;';
        echo "\n";
    }
    $cnt++;
}
?>

function startiframe(tabid) {
    var ifrm = $('#tab' + tabid + ' iframe');
    if(ifrm.attr('src')) return;
    ifrm.attr('src', urls[tabid]);
}
function activateTab(tabid) {
     $('.nav-tabs a[href="#tab' + tabid + '"]').tab('show');
}
function start_nondefault_iframe() {
    urls.forEach(function(item, index) {
        if(index != default_tab) startiframe(index);
    });
}

$(function(){
    activateTab(default_tab);
    startiframe(default_tab);
    setTimeout(start_nondefault_iframe,10000);

    $('.nav-tabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        var id = $(e.target).data('tid'); // activated tab id
        startiframe(id);
    });
});
</script>

<div class="panel with-nav-tabs panel-default">
    <div class="panel-heading">
            <ul class="nav nav-tabs">
<?php
$cnt = 0;
foreach($auth_methods as $auth_method) {
?>
            <li><a href="#tab<?php echo $cnt; ?>" data-toggle="tab" data-tid="<?php echo $cnt; ?>"><?php echo $this->t($auth_method['label_tag']); ?></a></li>

<?php
$cnt++;
}
?>            
    </div>
    <div class="panel-body">
        <div class="tab-content">

<?php
$cnt = 0;
foreach($auth_methods as $auth_method) {
?>
            <div class="tab-pane fade" id="tab<?php echo $cnt; ?>">
            <iframe frameborder="0" seamless="seamless" style="height: 335px;" class="center-block" width="100%" marginheight="0">
            </iframe>
            </div>

<?php
$cnt++;
 }
?>


        </div>
    </div>
</div>


 <?php
 $this->includeAtTemplateBase('remote:includes/footer.php');