<?php
$this->data['header'] = $this->t($this->data['auth_group']['label_tag']);
$this->data['jquery'] = array('core' => TRUE, 'ui' => TRUE, 'css' => TRUE);
$this->includeAtTemplateBase('includes/header.php');

$auth_methods = $this->data['auth_group']['auth_methods'];
$auth_preferred_method = $this->data['preferred'];
?>

<script type="text/javascript">
window.addEventListener("message", receiveMessage, false);

function receiveMessage(event)
{
    window.location.href = event.data;
}

var default_tab = 0;

var urls  = [];
<?php
$cnt = 0;
foreach($auth_methods as $auth_method) {
    echo 'urls.push(\'' . $auth_method['url'] . '?stateID=' . $this->data['stateid'] . '\');';
    echo "\n";
    if($cnt == $auth_preferred_method) {
        echo 'default_tab = ' . $cnt . ';';
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
    $( "#tabs" ).tabs( "select", tabid );
}
function start_nondefault_iframe() {
    urls.forEach(function(item, index) {
        if(index != default_tab) startiframe(index);
    });
}

$(function(){
    $( "#tabs" ).tabs();
    activateTab(default_tab);
    startiframe(default_tab);
    //setTimeout(start_nondefault_iframe,10000);

    $( "#tabs" ).on( "tabsselect", function( event, ui ) {
        startiframe(ui.tab.dataset.tid);
    } );

});
</script>

<div id="tabs">
        <ul>
<?php
$cnt = 0;
foreach($auth_methods as $auth_method) {
?>
            <li><a href="#tab<?php echo $cnt; ?>" data-tid="<?php echo $cnt; ?>"><?php echo $this->t($auth_method['label_tag']); ?></a></li>
<?php
$cnt++;
}
?>            
    </ul>

<?php
$cnt = 0;
foreach($auth_methods as $auth_method) {
?>
            <div id="tab<?php echo $cnt; ?>">
            <iframe frameborder="0" seamless="seamless" style="height: 435px;" class="center-block" width="100%" marginheight="0">
            </iframe>
            </div>
<?php
$cnt++;
 }
?>

</div>


 <?php

 
$this->includeAtTemplateBase('includes/footer.php');