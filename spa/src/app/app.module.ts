import { NgModule } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HttpClientXsrfModule, HTTP_INTERCEPTORS } from '@angular/common/http';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { GatewayInterceptor } from './interceptors/gateway.interceptor';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    ReactiveFormsModule,
    HttpClientModule,
    HttpClientXsrfModule.withOptions({
      cookieName: 'CSRF-TOKEN',
      headerName: 'X-CSRF-TOKEN'
    }),
    AppRoutingModule,
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: GatewayInterceptor, multi: true }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
