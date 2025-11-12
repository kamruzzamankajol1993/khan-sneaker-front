    
    <footer class="footer-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
                    <div class="footer-logo-container d-flex justify-content-center align-items-center flex-column">
                        <img src="{{$front_ins_url}}public/black.png" alt="Spotlight Attires" class="footer-logo">
                        <div class="footer-social-icons">
                                                                                                 @if(isset($socialLinks) && !$socialLinks->isEmpty())
                                @foreach($socialLinks as $link)
                                    <a href="{{ $link->link }}" target="_blank" title="{{ $link->title }}"><i class="bi bi-{{ strtolower($link->title) }}"></i></a>
                                @endforeach
                            @endif
                                                                                    </div>
                    </div>
                </div>
                <!-- Contact Cards -->
                <div class="col-md-4">
                    <div class="contact-card">
                        <div class="icon-circle">
                            <i class="bi bi-geo-alt-fill"></i>
                        </div>
                        <div class="contact-info">
                           {{$front_ins_add}}
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="contact-card">
                        <div class="icon-circle">
                            <i class="bi bi-envelope-fill"></i>
                        </div>
                        <div class="contact-info">
                          {{$front_ins_email}}
                           {{-- Display secondary email if it exists --}}
                       @if(!empty($front_ins_email_one))
                            <br>{{$front_ins_email_one}}
                       @endif
                           
                                               </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="contact-card">
                        <div class="icon-circle">
                            <i class="bi bi-telephone-fill"></i>
                        </div>
                        <div class="contact-info">
                        {{$front_ins_phone}}
                          @if(!empty($front_ins_phone_one))
                        <br>{{$front_ins_phone_one}}
                     @endif
                                             </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-12">
                    <div class="footer-bottom-text">
                        Copyright© 2025 Spotlight Attires
                    </div>
                </div>
            </div>
        </div>
    </footer>
    
    
